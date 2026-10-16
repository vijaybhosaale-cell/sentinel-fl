PY ?= python3
.PHONY: cluster aggregator bank-a bank-b bank-c monitoring install test baselines run dp defended demo serve matrix verify docker
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
cluster:    ; $(PY) -m sentinel cluster --fresh
aggregator: ; $(PY) -m sentinel aggregator --fresh
AGG ?= http://127.0.0.1:8000
bank-a:     ; $(PY) -m sentinel bank --id A --aggregator $(AGG) --port 8101
bank-b:     ; $(PY) -m sentinel bank --id B --aggregator $(AGG) --port 8102
bank-c:     ; $(PY) -m sentinel bank --id C --aggregator $(AGG) --port 8103
monitoring: ; docker compose --profile monitoring up --build
