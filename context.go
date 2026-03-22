package hclconfig

import (
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// newBaseEvalContext creates an EvalContext with the built-in env() function
// and merges any user-supplied context.
func newBaseEvalContext(userCtx *hcl.EvalContext) *hcl.EvalContext {
	ctx := &hcl.EvalContext{
		Variables: make(map[string]cty.Value),
		Functions: map[string]function.Function{
			"env":     envFunction(),
			"decrypt": decryptFunction(),
		},
	}

	if userCtx != nil {
		for k, v := range userCtx.Variables {
			ctx.Variables[k] = v
		}
		for k, v := range userCtx.Functions {
			ctx.Functions[k] = v
		}
	}

	return ctx
}

func decryptFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "ciphertext", Type: cty.String},
			{Name: "key", Type: cty.String},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			plaintext, err := Decrypt(args[0].AsString(), args[1].AsString())
			if err != nil {
				return cty.NilVal, err
			}
			return cty.StringVal(plaintext), nil
		},
	})
}

func envFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "name",
				Type: cty.String,
			},
		},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			name := args[0].AsString()
			return cty.StringVal(os.Getenv(name)), nil
		},
	})
}
