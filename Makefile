DRAFT = draft-iqbal-rosomakho-ai-security-events-00

all: build

build:
	kramdown-rfc2629 $(DRAFT).md > $(DRAFT).xml
	xml2rfc $(DRAFT).xml --text --html

clean:
	rm -f $(DRAFT).xml $(DRAFT).txt $(DRAFT).html

