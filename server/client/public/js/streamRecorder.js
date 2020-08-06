// With heavy inspiration from https://github.com/closeio/mic-recorder-to-mp3

// From https://gabrielpoca.com/2014-06-24-streaming-microphone-from-browser-to-nodejs-no-plugin/
function convertFloat32ToInt16(buffer) {
    var l = buffer.length;
    var buf = new Int16Array(l * 2);
    while (l--) {
        var s = buffer[l]; 
        var v = s < 0 ? s * 32768 : s * 32767;
        var i = Math.max(-32768, Math.min(32768, v));
        buf[l*2] = i;
        buf[l*2-1] = i;
    }
    return buf.buffer;
}

class StreamRecorder {
    constructor(socket) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        this.context = new AudioContext();
        this.stream = null;
        this.microphone = null;
        this.processor = null;
        this.socket = socket;
        this.recordingID = null;
    }

    record(stream) {
        // Retain microphone stream
        this.stream = stream;

        // Set up Web Audio API to process data from the media stream (microphone)
        this.microphone = this.context.createMediaStreamSource(stream);

        // Settings a bufferSize of 0 instructs the browser to choose the best bufferSize
        this.processor = this.context.createScriptProcessor(0, 1, 1);

        this.processor.onaudioprocess = (event) => {
            // Get audio buffer
            var channelData = event.inputBuffer.getChannelData(0);
            
            // Convert audio buffer to PCM
            var pcmData = convertFloat32ToInt16(channelData);

            // Send audio buffer to backend
            this.socket.emit(this.recordingID, pcmData);
        };

        // Begin retrieving microphone data
        this.microphone.connect(this.processor);
        this.processor.connect(this.context.destination);
    }

    start() {
        // Get microphone and begin recording
        return new Promise(function(resolve, reject) {
            // Setup recordingID receiver
            var receiveRecordingID = function (data) {
                // Save off recordingID
                this.recordingID = data.recordingID;
                console.log("starting recording with recordingID", this.recordingID);

                // Start recording
                navigator.mediaDevices.getUserMedia({ audio: true })
                    .then(function (stream) {
                        this.record(stream);
                        resolve(stream);
                    }.bind(this)).catch(function (err) {
                        reject(err);
                    });

                // Clear listener
                this.socket.removeListener(receiveRecordingID);
            }.bind(this);

            this.socket.on("newRecording", receiveRecordingID);

            // Setup a new recording
            this.socket.emit("setupRecording", "");
        }.bind(this));
    }

    stop() {
        if (this.processor && this.microphone) {
            // Clean up nodes.
            this.microphone.disconnect();
            this.processor.disconnect();

            this.processor.onaudioprocess = null;

            // Stop all audio tracks. Also, removes recording icon from Chrome tab.
            this.stream.getAudioTracks().forEach(track => track.stop());
        }

        return this;
    }
}
