.PHONY: compile clean release test dialyzer typer

REBAR ?= rebar3

compile:
	@$(REBAR) compile

clean:
	-@$(RM) -rf _rel
	@$(REBAR) clean

release:
	@$(REBAR) release

test:
	@$(REBAR) xref eunit

dialyzer: $(DEPSOLVER_PLT)
	@$(REBAR) dialyzer

typer:
	@typer \
        -pa _build/default/lib/seds/ebin \
        -pa _build/default/lib/lager/ebin \
        -I include \
        --plt _build/default/*_plt \
        -r ./src
