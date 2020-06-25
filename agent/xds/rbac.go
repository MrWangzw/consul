package xds

import (
	"fmt"
	"strings"

	envoylistener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	envoyroute "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	envoyhttprbac "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/rbac/v2"
	envoyhttp "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	envoynetrbac "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/rbac/v2"
	envoyrbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	celcommon "github.com/google/cel-go/common"
	celparser "github.com/google/cel-go/parser"
	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/go-hclog"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Requires 1.12+
//
// L4: https://www.envoyproxy.io/docs/envoy/v1.12.0/configuration/listeners/network_filters/rbac_filter
//
// L7: https://www.envoyproxy.io/docs/envoy/v1.12.0/configuration/http/http_filters/rbac_filter
//
// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/rbac_filter

func makeRBACHTTPFilter(cfgSnap *proxycfg.ConfigSnapshot, logger hclog.Logger) (*envoyhttp.HttpFilter, error) {
	rules, err := makeRBACRules(cfgSnap, logger, true)
	if err != nil {
		return nil, err
	}

	cfg := &envoyhttprbac.RBAC{
		Rules: rules,
		// ShadowRules: &rules, // TODO
	}
	return makeEnvoyHTTPFilter("envoy.filters.http.rbac", cfg)
}

func makeRBACNetworkFilter(cfgSnap *proxycfg.ConfigSnapshot, logger hclog.Logger) (*envoylistener.Filter, error) {
	rules, err := makeRBACRules(cfgSnap, logger, false)
	if err != nil {
		return nil, err
	}

	cfg := &envoynetrbac.RBAC{
		StatPrefix: "connect_authz",
		Rules:      rules,
		// ShadowRules: rules, // TODO
	}
	return makeFilter("envoy.filters.network.rbac", cfg)
}

func makeSpiffePattern(sourceNS, sourceName string) string {
	const anyPath = `[^/]+`
	switch {
	case sourceNS != structs.WildcardSpecifier && sourceName != structs.WildcardSpecifier:
		return fmt.Sprintf(`^spiffe://%s/ns/%s/dc/%s/svc/%s$`, anyPath, sourceNS, anyPath, sourceName)
	case sourceNS != structs.WildcardSpecifier && sourceName == structs.WildcardSpecifier:
		return fmt.Sprintf(`^spiffe://%s/ns/%s/dc/%s/svc/%s$`, anyPath, sourceNS, anyPath, anyPath)
	case sourceNS == structs.WildcardSpecifier && sourceName == structs.WildcardSpecifier:
		return fmt.Sprintf(`^spiffe://%s/ns/%s/dc/%s/svc/%s$`, anyPath, anyPath, anyPath, anyPath)
	default:
		panic("TODO(rbac-ixns): not possible")
	}
}

// Requires 1.12+
//
// L4: https://www.envoyproxy.io/docs/envoy/v1.12.0/configuration/listeners/network_filters/rbac_filter
//
// L7: https://www.envoyproxy.io/docs/envoy/v1.12.0/configuration/http/http_filters/rbac_filter
//
// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/rbac_filter
func makeRBACRules(cfgSnap *proxycfg.ConfigSnapshot, logger hclog.Logger, isHTTP bool) (*envoyrbac.RBAC, error) {
	//TODO(rbac-ixns)

	// Note that we DON'T explicitly validate the trust-domain matches ours. See
	// the PR for this change for details.

	// TODO(banks): Implement revocation list checking here.

	var cm celMemory

	cm.SetIntentions(cfgSnap.Intentions, isHTTP)

	rbacAction := cm.FlattenForDefaultPolicy(cfgSnap.DefaultACLPolicy)
	policies, err := cm.GenerateRBACPolicies()
	if err != nil {
		return nil, err
	}

	return &envoyrbac.RBAC{
		Action:   rbacAction,
		Policies: policies,
	}, nil
}

func (m *celMemory) GenerateRBACPolicies() (map[string]*envoyrbac.Policy, error) {
	policies := make(map[string]*envoyrbac.Policy)

	env, err := cel.NewEnv(cel.Macros(m.MacroExpander()))
	if err != nil {
		return nil, err
	}

	for i, snip := range m.snippets {
		ast, issues := env.Parse(snip.identityClause)
		if issues.Err() != nil {
			// TODO(rbac): better error context
			return nil, issues.Err()
		}

		policy := &envoyrbac.Policy{
			Principals: []*envoyrbac.Principal{
				{Identifier: &envoyrbac.Principal_Any{Any: true}},
				// {Identifier: &envoyrbac.Principal_Authenticated_{
				// 	Authenticated: &envoyrbac.Principal_Authenticated{
				// 		PrincipalName: &envoymatcher.StringMatcher{
				// 			MatchPattern: &envoymatcher.StringMatcher_Regex{
				// 				Regex: principalPatt,
				// 			},
				// 		},
				// 	},
				// }},
			},
			Condition: ast.Expr(),
		}
		if snip.permission != nil {
			policy.Permissions = []*envoyrbac.Permission{snip.permission}
		} else {
			policy.Permissions = []*envoyrbac.Permission{
				{Rule: &envoyrbac.Permission_Any{Any: true}},
			}
		}

		policyID := fmt.Sprintf("consul-compiled-intentions-%d", i)

		policies[policyID] = policy
	}

	return policies, nil
}

type celMemory struct {
	snippets        []*celSnippet
	stringConstants []string
}

func (m *celMemory) AddStringConstant(v string) int {
	constantID := len(m.stringConstants)
	m.stringConstants = append(m.stringConstants, v)
	return constantID
}

func (m *celMemory) MacroExpander() celparser.Macro {
	return celparser.NewGlobalMacro("stringvar", 1, stringIDMacroExpander(m.stringConstants))
}

func (m *celMemory) SetIntentions(ixns structs.Intentions, isHTTP bool) error {
	m.stringConstants = make([]string, 0, len(ixns))
	for _, ixn := range ixns {
		// we only care about the source end here; the dest was taken care of by the rest

		snippet := &celSnippet{
			allow:      (ixn.Action == structs.IntentionActionAllow),
			precedence: ixn.Precedence,
		}

		snippet.identityClause = fmt.Sprintf(
			"matches(connection.uri_san_peer_certificate, stringvar(%d))",
			m.AddStringConstant(
				makeSpiffePattern(ixn.SourceNS, ixn.SourceName),
			),
		)

		if isHTTP {
			if len(ixn.RouteMatches) > 0 {
				perm, err := m.generatePermission(ixn)
				if err != nil {
					return err
				}
				snippet.permission = perm
			}
		}

		m.snippets = append(m.snippets, snippet)
	}

	return nil
}

// TODO: do smooshing as well
func (m *celMemory) generatePermission(ixn *structs.Intention) (*envoyrbac.Permission, error) {
	if len(ixn.RouteMatches) == 0 {
		return nil, nil
	}

	// TODO(l7-ixn) handle default-allow

	var orRules []*envoyrbac.Permission
	for _, routeMatch := range ixn.RouteMatches {
		if routeMatch.HTTP == nil {
			continue // not possible
		}
		matchHTTP := routeMatch.HTTP

		var andRules []*envoyrbac.Permission
		andHeader := func(em *envoyroute.HeaderMatcher) {
			andRules = append(andRules, &envoyrbac.Permission{
				Rule: &envoyrbac.Permission_Header{
					Header: em,
				},
			})
		}

		// // Handle path portion of intention.
		if matchHTTP.PathExact != "" {
			andHeader(&envoyroute.HeaderMatcher{
				Name: ":path",
				HeaderMatchSpecifier: &envoyroute.HeaderMatcher_ExactMatch{
					ExactMatch: matchHTTP.PathExact,
				},
			})
		} else if matchHTTP.PathPrefix != "" {
			andHeader(&envoyroute.HeaderMatcher{
				Name: ":path",
				HeaderMatchSpecifier: &envoyroute.HeaderMatcher_PrefixMatch{
					PrefixMatch: matchHTTP.PathPrefix,
				},
			})
		} else if matchHTTP.PathRegex != "" {
			andHeader(&envoyroute.HeaderMatcher{
				Name: ":path",
				HeaderMatchSpecifier: &envoyroute.HeaderMatcher_RegexMatch{
					RegexMatch: matchHTTP.PathRegex,
				},
			})
		}

		if len(matchHTTP.Header) > 0 {
			for _, hdr := range matchHTTP.Header {
				em := &envoyroute.HeaderMatcher{
					Name: hdr.Name,
				}

				switch {
				case hdr.Present:
					em.HeaderMatchSpecifier = &envoyroute.HeaderMatcher_PresentMatch{
						PresentMatch: true,
					}
				case hdr.Exact != "":
					em.HeaderMatchSpecifier = &envoyroute.HeaderMatcher_ExactMatch{
						ExactMatch: hdr.Exact,
					}
				case hdr.Prefix != "":
					em.HeaderMatchSpecifier = &envoyroute.HeaderMatcher_PrefixMatch{
						PrefixMatch: hdr.Prefix,
					}
				case hdr.Suffix != "":
					em.HeaderMatchSpecifier = &envoyroute.HeaderMatcher_SuffixMatch{
						SuffixMatch: hdr.Suffix,
					}
				case hdr.Regex != "":
					em.HeaderMatchSpecifier = &envoyroute.HeaderMatcher_RegexMatch{
						RegexMatch: hdr.Regex,
					}
				default:
					continue // skip this impossible situation
				}

				if hdr.Invert {
					em.InvertMatch = true
				}

				andRules = append(andRules, &envoyrbac.Permission{
					Rule: &envoyrbac.Permission_Header{
						Header: em,
					},
				})
			}
		}

		if len(matchHTTP.Methods) > 0 {
			andRules = append(andRules, &envoyrbac.Permission{
				Rule: &envoyrbac.Permission_Header{
					Header: &envoyroute.HeaderMatcher{
						Name: ":method",
						HeaderMatchSpecifier: &envoyroute.HeaderMatcher_RegexMatch{
							RegexMatch: strings.Join(matchHTTP.Methods, "|"),
						},
					},
				},
			})
		}

		// TODO(l7-ixn): can we do queryparam matches?
		if len(matchHTTP.QueryParam) > 0 {
			panic("SORRY")
		}

		if len(andRules) > 0 {
			orRules = append(orRules, &envoyrbac.Permission{
				Rule: &envoyrbac.Permission_AndRules{
					AndRules: &envoyrbac.Permission_Set{
						Rules: andRules,
					},
				},
			})
		}
	}

	permStruct := &envoyrbac.Permission{
		Rule: &envoyrbac.Permission_OrRules{
			OrRules: &envoyrbac.Permission_Set{
				Rules: orRules,
			},
		},
	}

	return permStruct, nil
}

// Normalize: if we are in default-deny, all of our actual clauses must be allows
//
// IDENTITY is the only thing we care about here.
func (m *celMemory) FlattenForDefaultPolicy(defaultACLPolicy acl.EnforcementDecision) envoyrbac.RBAC_Action {
	if defaultACLPolicy == acl.Deny {
		// First we walk in descending precedence and squish denies into the
		// allows that follow. This makes sense because in the common case the
		// root will be default-deny, and our RBAC will be just listing all
		// conditions that are ALLOWED.
		if len(m.snippets) > 0 {
			mod := make([]*celSnippet, 0, len(m.snippets))
			for i, snip := range m.snippets {
				if snip.allow {
					mod = append(mod, snip)
				} else {
					if snip.permission != nil {
						panic("oops; what does this even mean?")
					}
					for j := i + 1; j < len(m.snippets); j++ {
						snip2 := m.snippets[j]

						snip2.identityClause = "(" + snip2.identityClause + ") AND !(" + snip.identityClause + ")"
					}
					// since this is default-deny, any trailing denies will just evaporate
				}
			}
			m.snippets = mod
		}

		if len(m.snippets) > 1 {
			// Remove precedence with logic.
			//
			// If we have L7 conditions, act like we had
			// an L7 intention and an L4 intention with the opposite
			// action immediately following it.
			for i, snip := range m.snippets {
				if !snip.allow {
					panic("oops") // TODO
				}
				for j := i + 1; j < len(m.snippets); j++ {
					snip2 := m.snippets[j]
					snip2.identityClause = "(" + snip2.identityClause + ") AND !(" + snip.identityClause + ")"
				}
			}
		}

		// Note this feels a little bit backwards.
		//
		// The RBAC policies grant access to principals. The rest is denied.
		// This is safe-list style access control. This is the default type.
		return envoyrbac.RBAC_ALLOW

	} else {
		panic("TODO")

		// The RBAC policies deny access to principals. The rest is allowed.
		// This is block-list style access control.
		//
		// return envoyrbac.RBAC_DENY
	}
}

type celSnippet struct {
	identityClause string // CEL
	allow          bool
	precedence     int // TODO(rbac-ixns): use this to optimize how the collapse works

	permission *envoyrbac.Permission
}

// stringIDMacroExpander returns a macro expander that accepts 1 numeric
// argument and looks that up by index in a table of strings and returns that
// instead.
func stringIDMacroExpander(stringsByID []string) celparser.MacroExpander {
	return func(eh celparser.ExprHelper, _ *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *celcommon.Error) {
		constExpr, ok := args[0].ExprKind.(*exprpb.Expr_ConstExpr)
		if !ok {
			location := eh.OffsetLocation(args[0].Id)
			return nil, &common.Error{
				Message:  "argument must be a constant",
				Location: location,
			}
		}
		int64Const, ok := constExpr.ConstExpr.ConstantKind.(*exprpb.Constant_Int64Value)
		if !ok {
			location := eh.OffsetLocation(args[0].Id)
			return nil, &common.Error{
				Message:  "argument must be an int64 constant",
				Location: location,
			}
		}
		constantID := int(int64Const.Int64Value)
		if constantID < 0 || constantID >= len(stringsByID) {
			location := eh.OffsetLocation(args[0].Id)
			return nil, &common.Error{
				Message:  fmt.Sprintf("stringvar %d does not exist", constantID),
				Location: location,
			}
		}
		v := stringsByID[constantID]

		return eh.LiteralString(v), nil
	}
}
