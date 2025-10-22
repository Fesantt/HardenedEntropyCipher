CC      = gcc
CFLAGS  = -O3 -march=native -flto -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS = -pie -static -Wl,-z,relro,-z,now,-z,noexecstack
LIBS    = -lsodium -lm
SRC     = cipher.c
OUT     = v3

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OUT)
