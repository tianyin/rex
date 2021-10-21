

docker: Dockerfile
	docker build -t libbpf-bootstrap-example-builder .

examples:
	docker run --rm -v ~/libbpf-bootstrap:/libbpf-bootstrap libbpf-bootstrap-example-builder make

examples-clean:
	docker run --rm -v ~/libbpf-bootstrap:/libbpf-bootstrap libbpf-bootstrap-example-builder make clean

