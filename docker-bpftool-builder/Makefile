

docker: Dockerfile
	docker build -t bpftool-builder .

bpftool:
	docker run --rm -v ~/linux:/linux bpftool-builder make bpftool

bpftool-clean:
	docker run --rm -v ~/linux:/linux bpftool-builder make clean
