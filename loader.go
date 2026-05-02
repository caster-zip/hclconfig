package hclconfig

import (
	"fmt"
	"os"
	"reflect"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Option configures the behavior of Load/LoadFile.
type Option func(*options)

type options struct {
	evalCtx       *hcl.EvalContext
	encryptionKey string
}

// WithEvalContext provides a custom HCL EvalContext that will be merged with
// the built-in context (env function, resolved block variables).
func WithEvalContext(ctx *hcl.EvalContext) Option {
	return func(o *options) {
		o.evalCtx = ctx
	}
}

// WithEncryptionKey sets the base64-encoded encryption key used to decrypt
// CIPHER["..."] sentinels at load time. If unset, the key is read from the
// HCLCONFIG_KEY environment variable.
func WithEncryptionKey(key string) Option {
	return func(o *options) {
		o.encryptionKey = key
	}
}

// LoadFile reads and parses an HCL file with cross-block variable resolution.
func LoadFile(filename string, dst interface{}, opts ...Option) error {
	src, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filename, err)
	}
	return Load(src, filename, dst, opts...)
}

// Load parses HCL source bytes with cross-block variable resolution.
func Load(src []byte, filename string, dst interface{}, opts ...Option) error {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	// 1. Parse
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return &DiagnosticsError{Diags: diags}
	}

	body := file.Body

	// 2. Build full schema: user blocks + all top-level attributes (struct + free variables)
	schema, _ := gohcl.ImpliedBodySchema(dst)
	syntaxBody, ok := body.(*hclsyntax.Body)
	if !ok {
		return fmt.Errorf("unexpected body type %T; expected *hclsyntax.Body", body)
	}

	// Resolve secret sentinels (CIPHER["..."] / PLAIN["..."]) before evaluation.
	key := o.encryptionKey
	if key == "" {
		key = envEncryptionKey()
	}
	cipherMap, err := resolveCipherSentinel(syntaxBody, key)
	if err != nil {
		return err
	}
	for name := range syntaxBody.Attributes {
		if !schemaHasAttr(schema, name) {
			schema.Attributes = append(schema.Attributes, hcl.AttributeSchema{Name: name})
		}
	}
	content, diags := body.Content(schema)
	if diags.HasErrors() {
		return &DiagnosticsError{Diags: diags}
	}

	// allAttrs is content.Attributes (contains both struct-matched and free variables)
	allAttrs := content.Attributes

	// 5. Build block info lists
	userBlockInfos := make([]blockInfo, len(content.Blocks))
	for i, block := range content.Blocks {
		label := ""
		if len(block.Labels) > 0 {
			label = block.Labels[0]
		}
		userBlockInfos[i] = blockInfo{
			typeName: block.Type,
			label:    label,
			index:    i,
		}
	}

	// 6. Build dependency graph and topological sort
	deps := buildDependencyGraph(content.Blocks, userBlockInfos, allAttrs)

	var allInfos []blockInfo
	allInfos = append(allInfos, userBlockInfos...)
	for name := range allAttrs {
		allInfos = append(allInfos, blockInfo{typeName: name, isAttr: true})
	}

	sortedKeys, err := topoSort(allInfos, deps)
	if err != nil {
		return err
	}

	// 7. Build eval context
	evalCtx := newBaseEvalContext(o.evalCtx)
	if cipherMap != cty.NilVal {
		evalCtx.Variables[SentinelCipher] = cipherMap
	}

	// 8. Decode in topological order (both blocks and attributes)
	dstVal := reflect.ValueOf(dst).Elem()
	dstType := dstVal.Type()

	// Build maps from name -> field info for blocks and attributes
	type fieldInfo struct {
		fieldIndex int
		isSlice    bool
		isPtr      bool
	}
	blockFieldMap := make(map[string]fieldInfo)
	attrFieldMap := make(map[string]int) // attr name -> struct field index
	for i := 0; i < dstType.NumField(); i++ {
		field := dstType.Field(i)
		tag := field.Tag.Get("hcl")
		if tag == "" {
			continue
		}
		name, kind := parseHCLTag(tag)
		switch kind {
		case "block":
			ft := field.Type
			isPtr := ft.Kind() == reflect.Ptr
			isSlice := ft.Kind() == reflect.Slice
			blockFieldMap[name] = fieldInfo{
				fieldIndex: i,
				isSlice:    isSlice,
				isPtr:      isPtr,
			}
		case "attr", "optional":
			attrFieldMap[name] = i
		}
	}

	// Build set of attribute names for dispatch in the decode loop
	attrNames := make(map[string]bool)
	for name := range allAttrs {
		attrNames[name] = true
	}

	// Group user blocks by key for decoding
	blocksByKey := make(map[string][]*hcl.Block)
	blockInfoByKey := make(map[string][]blockInfo)
	for i, bi := range userBlockInfos {
		key := bi.key()
		blocksByKey[key] = append(blocksByKey[key], content.Blocks[i])
		blockInfoByKey[key] = append(blockInfoByKey[key], bi)
	}

	for _, key := range sortedKeys {
		// --- Top-level attribute (struct-matched or free variable) ---
		if attrNames[key] {
			attr := allAttrs[key]
			val, diags := attr.Expr.Value(evalCtx)
			if diags.HasErrors() {
				return &DiagnosticsError{Diags: diags}
			}
			if fi, ok := attrFieldMap[key]; ok {
				if err := setCtyValueOnField(dstVal.Field(fi), val); err != nil {
					r := attr.Expr.Range()
					return fmt.Errorf("%s:%d,%d: attribute %q: %w", r.Filename, r.Start.Line, r.Start.Column, key, err)
				}
			}
			evalCtx.Variables[key] = val
			continue
		}

		// --- Block ---
		blocks := blocksByKey[key]
		if len(blocks) == 0 {
			continue
		}

		typeName := blocks[0].Type
		fi, ok := blockFieldMap[typeName]
		if !ok {
			continue
		}

		fieldVal := dstVal.Field(fi.fieldIndex)

		if fi.isSlice {
			err := decodeSliceBlocks(fieldVal, blocks, evalCtx)
			if err != nil {
				return err
			}
		} else if fi.isPtr {
			elemType := fieldVal.Type().Elem()
			newVal := reflect.New(elemType)
			diags := gohcl.DecodeBody(blocks[0].Body, evalCtx, newVal.Interface())
			if diags.HasErrors() {
				return wrapBlockDiags(blocks[0], diags)
			}
			fieldVal.Set(newVal)
		} else {
			diags := gohcl.DecodeBody(blocks[0].Body, evalCtx, fieldVal.Addr().Interface())
			if diags.HasErrors() {
				return wrapBlockDiags(blocks[0], diags)
			}
		}

		// After decoding block, add to eval context
		infos := blockInfoByKey[key]
		if fi.isSlice && len(infos) > 0 && infos[0].label != "" {
			addLabeledSliceToEvalCtx(evalCtx, typeName, fieldVal)
		} else if fi.isSlice {
			val, err := structToCtyValue(fieldVal.Interface())
			if err == nil && val != cty.NilVal {
				evalCtx.Variables[typeName] = val
			}
		} else {
			var iface interface{}
			if fi.isPtr {
				if !fieldVal.IsNil() {
					iface = fieldVal.Elem().Interface()
				}
			} else {
				iface = fieldVal.Interface()
			}
			if iface != nil {
				val, err := structToCtyValue(iface)
				if err == nil && val != cty.NilVal {
					evalCtx.Variables[typeName] = val
				}
			}
		}
	}

	return nil
}

// setCtyValueOnField sets a struct field from a cty.Value.
func setCtyValueOnField(fieldVal reflect.Value, val cty.Value) error {
	switch fieldVal.Kind() {
	case reflect.String:
		fieldVal.SetString(val.AsString())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bf := val.AsBigFloat()
		i, _ := bf.Int64()
		fieldVal.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		bf := val.AsBigFloat()
		u, _ := bf.Uint64()
		fieldVal.SetUint(u)
	case reflect.Float32, reflect.Float64:
		bf := val.AsBigFloat()
		f, _ := bf.Float64()
		fieldVal.SetFloat(f)
	case reflect.Bool:
		fieldVal.SetBool(val.True())
	case reflect.Slice:
		return setSliceFromCty(fieldVal, val)
	default:
		return fmt.Errorf("unsupported field kind %s", fieldVal.Kind())
	}
	return nil
}

func setSliceFromCty(fieldVal reflect.Value, val cty.Value) error {
	if !val.Type().IsListType() && !val.Type().IsTupleType() && !val.Type().IsSetType() {
		return fmt.Errorf("cannot convert %s to slice", val.Type().FriendlyName())
	}
	elems := val.AsValueSlice()
	slice := reflect.MakeSlice(fieldVal.Type(), len(elems), len(elems))
	for i, elem := range elems {
		if err := setCtyValueOnField(slice.Index(i), elem); err != nil {
			return fmt.Errorf("element %d: %w", i, err)
		}
	}
	fieldVal.Set(slice)
	return nil
}

func decodeSliceBlocks(fieldVal reflect.Value, blocks []*hcl.Block, evalCtx *hcl.EvalContext) error {
	elemType := fieldVal.Type().Elem()
	isElemPtr := elemType.Kind() == reflect.Ptr
	if isElemPtr {
		elemType = elemType.Elem()
	}

	for _, block := range blocks {
		newVal := reflect.New(elemType)
		// Set label fields before decoding
		setLabelFields(newVal.Elem(), block.Labels)

		diags := gohcl.DecodeBody(block.Body, evalCtx, newVal.Interface())
		if diags.HasErrors() {
			return wrapBlockDiags(block, diags)
		}

		if isElemPtr {
			fieldVal.Set(reflect.Append(fieldVal, newVal))
		} else {
			fieldVal.Set(reflect.Append(fieldVal, newVal.Elem()))
		}
	}
	return nil
}

func setLabelFields(rv reflect.Value, labels []string) {
	rt := rv.Type()
	labelIdx := 0
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("hcl")
		if tag == "" {
			continue
		}
		_, kind := parseHCLTag(tag)
		if kind == "label" && labelIdx < len(labels) {
			rv.Field(i).SetString(labels[labelIdx])
			labelIdx++
		}
	}
}

// wrapBlockDiags wraps decode diagnostics with block type, label, and definition range
// so that errors clearly identify which block caused the failure.
func wrapBlockDiags(block *hcl.Block, diags hcl.Diagnostics) error {
	label := ""
	if len(block.Labels) > 0 {
		label = fmt.Sprintf(" %q", block.Labels[0])
	}
	wrapped := make(hcl.Diagnostics, len(diags))
	for i, d := range diags {
		cp := *d
		detail := fmt.Sprintf("In %s%s block", block.Type, label)
		if d.Subject != nil {
			detail += fmt.Sprintf(" defined at %s:%d", d.Subject.Filename, d.Subject.Start.Line)
		} else {
			detail += fmt.Sprintf(" at %s:%d", block.DefRange.Filename, block.DefRange.Start.Line)
		}
		if d.Detail != "" {
			detail += ": " + d.Detail
		}
		cp.Detail = detail
		if cp.Subject == nil {
			cp.Subject = block.DefRange.Ptr()
		}
		wrapped[i] = &cp
	}
	return &DiagnosticsError{Diags: wrapped}
}

func addLabeledSliceToEvalCtx(evalCtx *hcl.EvalContext, typeName string, sliceVal reflect.Value) {
	labelMap := make(map[string]cty.Value)
	for i := 0; i < sliceVal.Len(); i++ {
		elem := sliceVal.Index(i)
		for elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}
		label := getLabelValue(elem)
		if label == "" {
			continue
		}
		val, err := structFieldsToCtyObject(elem)
		if err == nil && val != cty.NilVal {
			labelMap[label] = val
		}
	}
	if len(labelMap) > 0 {
		evalCtx.Variables[typeName] = cty.ObjectVal(labelMap)
	}
}

func schemaHasAttr(schema *hcl.BodySchema, name string) bool {
	for _, a := range schema.Attributes {
		if a.Name == name {
			return true
		}
	}
	return false
}
