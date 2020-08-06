import os
import uuid
import logging
import time
from flask_socketio import SocketIO, emit

from constants import *


MAX_WAV_SIZE = 4294967295
SAMPLE_RATE = 44100
BIT_DEPTH = 16
CHANNELS = 2


logger = logging.getLogger(FLASK_NAME)


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


def setup_recording(socketio, data):
    """
    Defines a recordingID to allow for a product audio notification to get the correct streaming recording.
    Sets up a socketio handler for receiving audio data.
    """
    # Create a unique ID
    recording_id = str(uuid.uuid4())
    
    # Send ID to client
    emit('newRecording', { "recordingID": recording_id })
    
    @socketio.on(recording_id)
    def _recording_data(data):
        file_path = f"{STREAMING_FILE_DIR}/{recording_id}"
        
        # Check for existence, write WAV header if new file
        if not os.path.exists(file_path):
            logger.info(f"writing new stream file: {recording_id}")
            # Create file with +
            with open(file_path, 'wb+') as f:
                f.write(generate_stream_wave_header())

        # Write data to file
        with open(file_path, 'ab') as f:
            f.write(data)


def get_stream(recording_id):
    """
    Reads from the streaming file and serves the audio notification to a product.
    """
    logger.info(f"streaming recording: {recording_id}")
    file_path = f"{STREAMING_FILE_DIR}/{recording_id}"

    # Check for recording
    if not os.path.exists(file_path):
        logger.info(f"file_path: {file_path} not found")
        return None
    
    def _stream():
        """Generator function that provides streaming audio data for the response."""
        CHUNK = 1024
        TIMEOUT_SEC = 0.5

        with open(file_path, 'rb') as f:
            last_data_read = 0
            while True:
                data = f.read(CHUNK)
                if data:
                    last_data_read = time.time()
                    yield data
                else:
                    # Allow time for write
                    time.sleep(TIMEOUT_SEC / 10.0)
                    if time.time() - last_data_read > TIMEOUT_SEC:
                        logger.info(f"file read timed out, deleting: {recording_id}")
                        break
        
        # Delete file
        os.remove(file_path)

    return _stream