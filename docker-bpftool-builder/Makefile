

docker: Dockerfile
	docker build -t bpftool-builder .

linux:
	docker run -v ~/linux:~/linux bpftool-builder make bpftool
