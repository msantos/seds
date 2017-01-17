.PHONY: compile clean release test dialyzer typer lint

REBAR ?= rebar3
ELVIS ?= elvis

compile:
	@$(REBAR) compile

clean:
	-@$(RM) -rf _rel
	@$(REBAR) clean

release:
	@$(REBAR) release

test:
	@$(REBAR) do xref, ct

dialyzer:
	@$(REBAR) dialyzer

lint:
	@$(ELVIS) rock

typer:
	@typer \
        -pa _build/default/lib/seds/ebin \
        -pa _build/default/lib/lager/ebin \
        -I include \
        --plt _build/default/*_plt \
        -r ./src
