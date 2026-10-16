PY ?= python3
.PHONY: install test baselines run dp defended demo serve matrix verify docker
install:   ; $(PY) -m pip install -r requirements.txt
test:      ; $(PY) -m unittest discover -s tests -v
baselines: ; $(PY) -m sentinel baselines --config configs/fedavg.yaml
run:       ; $(PY) -m sentinel run --config configs/fedavg.yaml
dp:        ; $(PY) -m sentinel run --config configs/fedprox_dp.yaml
defended:  ; $(PY) -m sentinel run --config configs/defended.yaml --set attack.type=label_flip
demo:      ; $(PY) -m sentinel demo
serve:     ; $(PY) -m sentinel serve
matrix:    ; $(PY) -m sentinel matrix
verify:    ; $(PY) -m sentinel verify --run demo
docker:    ; docker compose up --build
