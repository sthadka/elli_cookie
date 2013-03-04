SHELL := /bin/bash

REBAR=./rebar
APP=guinea

all: small_clean deps compile

deps:
	$(REBAR) get-deps

small_clean:
	$(REBAR) skip_deps=true clean

compile:
	rm -rf .eunit
	$(REBAR) compile

test:
	$(REBAR) skip_deps=true eunit

.PHONY: all small_clean compile deps test
