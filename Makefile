sjail: sjail.c
	gcc $< -o $@

.PHONY: clean
clean:
	rm sjail
