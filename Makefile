.PHONY: compile clean release test dialyzer typer

REBAR ?= rebar3
RELX ?= relx

compile:
	@$(REBAR) compile

clean:
	-@$(RM) -rf _rel
	@$(REBAR) clean

release:
	@$(RELX) --sys_config rel/sys.config release tar

test:
	@$(REBAR) xref eunit recursive=false

dialyzer: $(DEPSOLVER_PLT)
	@$(REBAR) dialyzer

typer:
	@typer \
        -pa _build/default/lib/seds/ebin \
        -I include \
        --plt _build/default/*_plt \
        -r ./src
