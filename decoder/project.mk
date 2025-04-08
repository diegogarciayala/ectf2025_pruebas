# Pass DECODER_ID from docker build
ifndef DECODER_ID
$(error DECODER_ID is not set. Must be passed in docker run)
endif

CFLAGS += -DDECODER_ID=$(DECODER_ID)