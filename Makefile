DRAFT = draft-iqbal-rosomakho-ai-security-events-00

all: build

build:
kramdown-rfc $(DRAFT).md > $(DRAFT).xml
xml2rfc $(DRAFT).xml --text --html

validate:
xml2rfc $(DRAFT).xml --v3 --strict

clean:
rm -f $(DRAFT).xml $(DRAFT).txt $(DRAFT).html
