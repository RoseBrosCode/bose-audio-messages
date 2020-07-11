// Original sample code from https://www.kirupa.com/html5/press_and_hold.htm
// also useful https://www.kirupa.com/html5/handling_events_for_many_elements.htm 

var buttons = document.querySelector("#buttons");
var recorder;
var filename;
var activeProduct;
var awsCreds = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: 'us-east-1:73bbe336-2fb5-4aa4-97a4-87c2e52e679c'
});
var awsConfig = new AWS.Config({
    credentials: awsCreds,
    region: 'us-east-1'
});
AWS.config.update(awsConfig);

// Listening for the mouse and touch events    
buttons.addEventListener("mousedown", pressingDown, false);
buttons.addEventListener("mouseup", notPressingDown, false);

buttons.addEventListener("touchstart", pressingDown, false);
buttons.addEventListener("touchend", notPressingDown, false);
document.oncontextmenu = function () { return false; };

window.onload = function () {
    // get audio stream from user's mic
    navigator.mediaDevices.getUserMedia({
        audio: true
    })
        .then(function (stream) {
            recorder = new MediaRecorder(stream);

            // listen to dataavailable, which gets triggered whenever we have
            // an audio blob available
            recorder.addEventListener('dataavailable', onRecordingReady);
        });
};

function preventMenu(e) {
    e.preventDefault && e.preventDefault();
    e.stopPropagation && e.stopPropagation();
    e.cancelBubble = true;
    e.returnValue = false;
    return false;
}

function pressingDown(e) {
    e.preventDefault();
    e.target.src = window.staticFilepath + "/images/" + $(e.target).attr("imageName") + "-recording.png";
    recorder.start();
    console.log("Pressing!");
}

function notPressingDown(e) {
    console.log("Not pressing!", e.target.id);
    activeProduct = e.target;
    e.target.src = window.staticFilepath + "/images/" + $(e.target).attr("imageName") + "-sending.png";

    // the timeout below is a hack that will need some love
    setTimeout(function () {
        console.log("Stopping!")
        recorder.stop();
    }, 1000);
}

function onRecordingReady(e) {
    // e.data contains a blob representing the recording
    var reader = new FileReader();
    var audioCtx = new AudioContext();

    reader.onloadend = function (e) {
        audioCtx.decodeAudioData(reader.result).then(function (decodedData) {
            var convertedWav = audioBufferToWav(decodedData);
            var convertedWavBlob = new Blob([convertedWav]);

            // upload to S3
            var uuid = generateUUID();
            // bam_msg_ prefixed objects are cleaned up after 1 day
            filename = "bam_msg_" + uuid + ".wav";
            var upload = new AWS.S3.ManagedUpload({
                params: {
                    Bucket: "bose-audio-messages",
                    Key: filename,
                    Body: convertedWavBlob,
                    ACL: "public-read"
                }
            });

            upload.promise().then(
                function (data) {
                    console.log("upload success! URL: ", data.Location);
                    console.log("product to sent to: ", activeProduct.id);

                    // TODO: poopulate with backend URL for sending AN
                    var playUrl = window.serverRoot + "send";

                    var message = {
                        "origin": "BAM Web App",
                        "key": filename
                    }
                    console.log(message);
                    fetch(playUrl, {
                        method: 'POST', // *GET, POST, PUT, DELETE, etc.
                        mode: 'no-cors',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(message)
                    }).then(() => {
                        $(`#${activeProduct.id}`)[0].src = window.staticFilepath + "/images/" + $(activeProduct.target).attr("imageName") + "-sent.png";

                        setTimeout(() => {
                            $(`#${activeProduct.id}`)[0].src = window.staticFilepath + "/images/" + $(activeProduct.target).attr("imageName") + ".png";
                        }, 5000);
                    });
                    
                },
                function (err) {
                    console.log("There was an error uploading the mesage: ", err.message);
                }
            );
        });
    };

    reader.readAsArrayBuffer(e.data);

}

// https://github.com/Jam3/audiobuffer-to-wav/blob/master/index.js
function audioBufferToWav(buffer, opt) {
    opt = opt || {}

    var numChannels = buffer.numberOfChannels
    var sampleRate = buffer.sampleRate
    var format = opt.float32 ? 3 : 1
    var bitDepth = format === 3 ? 32 : 16

    var result
    if (numChannels === 2) {
        result = interleave(buffer.getChannelData(0), buffer.getChannelData(1))
    } else {
        result = buffer.getChannelData(0)
    }

    return encodeWAV(result, format, sampleRate, numChannels, bitDepth)
}

function encodeWAV(samples, format, sampleRate, numChannels, bitDepth) {
    var bytesPerSample = bitDepth / 8
    var blockAlign = numChannels * bytesPerSample

    var buffer = new ArrayBuffer(44 + samples.length * bytesPerSample)
    var view = new DataView(buffer)

    /* RIFF identifier */
    writeString(view, 0, 'RIFF')
    /* RIFF chunk length */
    view.setUint32(4, 36 + samples.length * bytesPerSample, true)
    /* RIFF type */
    writeString(view, 8, 'WAVE')
    /* format chunk identifier */
    writeString(view, 12, 'fmt ')
    /* format chunk length */
    view.setUint32(16, 16, true)
    /* sample format (raw) */
    view.setUint16(20, format, true)
    /* channel count */
    view.setUint16(22, numChannels, true)
    /* sample rate */
    view.setUint32(24, sampleRate, true)
    /* byte rate (sample rate * block align) */
    view.setUint32(28, sampleRate * blockAlign, true)
    /* block align (channel count * bytes per sample) */
    view.setUint16(32, blockAlign, true)
    /* bits per sample */
    view.setUint16(34, bitDepth, true)
    /* data chunk identifier */
    writeString(view, 36, 'data')
    /* data chunk length */
    view.setUint32(40, samples.length * bytesPerSample, true)
    if (format === 1) { // Raw PCM
        floatTo16BitPCM(view, 44, samples)
    } else {
        writeFloat32(view, 44, samples)
    }

    return buffer
}

function interleave(inputL, inputR) {
    var length = inputL.length + inputR.length
    var result = new Float32Array(length)

    var index = 0
    var inputIndex = 0

    while (index < length) {
        result[index++] = inputL[inputIndex]
        result[index++] = inputR[inputIndex]
        inputIndex++
    }
    return result
}

function writeFloat32(output, offset, input) {
    for (var i = 0; i < input.length; i++ , offset += 4) {
        output.setFloat32(offset, input[i], true)
    }
}

function floatTo16BitPCM(output, offset, input) {
    for (var i = 0; i < input.length; i++ , offset += 2) {
        var s = Math.max(-1, Math.min(1, input[i]))
        output.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7FFF, true)
    }
}

function writeString(view, offset, string) {
    for (var i = 0; i < string.length; i++) {
        view.setUint8(offset + i, string.charCodeAt(i))
    }
}

// UUID gen
function generateUUID() { // Public Domain/MIT
    var d = new Date().getTime();//Timestamp
    var d2 = (performance && performance.now && (performance.now() * 1000)) || 0;//Time in microseconds since page-load or 0 if unsupported
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16;//random number between 0 and 16
        if (d > 0) {//Use timestamp until depleted
            r = (d + r) % 16 | 0;
            d = Math.floor(d / 16);
        } else {//Use microseconds since page-load if supported
            r = (d2 + r) % 16 | 0;
            d2 = Math.floor(d2 / 16);
        }
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}
