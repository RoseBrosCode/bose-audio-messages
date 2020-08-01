
MAX_WAV_SIZE = 4294967295
SAMPLE_RATE = 48000
BIT_DEPTH = 16
CHANNELS = 1

def generate_stream_wave_header(sample_rate=SAMPLE_RATE, bit_depth=BIT_DEPTH, channels=CHANNELS):
    """Creates a WAV header for a undefined-size (stream) file."""
    datasize = MAX_WAV_SIZE - 100                                       # Define size as long as possible, minus some buffer (header + buffer)
    o = bytes("RIFF",'ascii')                                           # (4byte) Marks file as RIFF
    o += (datasize + 36).to_bytes(4,'little')                           # (4byte) File size in bytes excluding this and RIFF marker
    o += bytes("WAVE",'ascii')                                          # (4byte) File type
    o += bytes("fmt ",'ascii')                                          # (4byte) Format chunk marker
    o += (16).to_bytes(4,'little')                                      # (4byte) Length of above format data
    o += (1).to_bytes(2,'little')                                       # (2byte) Format type (1 - PCM)
    o += (channels).to_bytes(2,'little')                                # (2byte) Number of channels
    o += (sample_rate).to_bytes(4,'little')                             # (4byte) Sample rate
    o += (sample_rate * channels * bit_depth // 8).to_bytes(4,'little') # (4byte) Byte rate
    o += (channels * bit_depth // 8).to_bytes(2,'little')               # (2byte) Block align
    o += (bit_depth).to_bytes(2,'little')                               # (2byte) Bit depth
    o += bytes("data",'ascii')                                          # (4byte) Data chunk marker
    o += (datasize).to_bytes(4,'little')                                # (4byte) Data size in bytes
    return o


