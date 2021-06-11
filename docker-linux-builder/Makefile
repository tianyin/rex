

docker: Dockerfile
	docker build -t linux-builder .

linux:
	docker run -v ~/linux:~/linux linux-builder make -j32 bzImage
