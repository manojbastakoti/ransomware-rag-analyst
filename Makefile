.PHONY: install index run eval test attack
install: ; pip install -r requirements.txt
attack:  ; python scripts/fetch_attack.py
index:   ; python scripts/build_index.py
run:     ; python app.py
eval:    ; python scripts/run_eval.py
test:    ; pytest
