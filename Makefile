REBAR=$(shell which rebar || echo ./rebar)
RELX=relx
DEPSOLVER_PLT=$(CURDIR)/.depsolver_plt

all: deps compile

./rebar:
	erl -noshell -s inets start -s ssl start \
		-eval 'httpc:request(get, {"https://raw.github.com/wiki/rebar/rebar/rebar", []}, [], [{stream, "./rebar"}])' \
		-s inets stop -s init stop
	chmod +x ./rebar

compile: $(REBAR)
	@$(REBAR) compile

clean: $(REBAR)
	-@$(RM) -rf _rel
	@$(REBAR) clean

deps: $(REBAR)
	@$(REBAR) check-deps || $(REBAR) get-deps

release:
	@$(RELX) --sys_config rel/sys.config release tar

test: $(REBAR) compile
	@$(REBAR) xref eunit recursive=false

.PHONY: test dialyzer typer clean distclean

$(DEPSOLVER_PLT):
	@dialyzer $(DIALYZER_FLAGS) --output_plt $(DEPSOLVER_PLT) --build_plt \
		--apps erts kernel stdlib crypto

dialyzer: $(DEPSOLVER_PLT)
	@dialyzer $(DIALYZER_FLAGS) -I include --plt $(DEPSOLVER_PLT) -Wrace_conditions --src src

typer: $(DEPSOLVER_PLT)
	@typer -I include --plt $(DEPSOLVER_PLT) -r ./src

distclean: clean
	@rm $(DEPSOLVER_PLT)
