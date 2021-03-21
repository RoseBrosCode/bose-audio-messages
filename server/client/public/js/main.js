// Original sample code from https://www.kirupa.com/html5/press_and_hold.htm
// also useful https://www.kirupa.com/html5/handling_events_for_many_elements.htm 

var buttons = document.querySelectorAll('[data-vendor]'); // only select the inputs themselves; they're the only thing with this attribute
var recorder;
var filename;
var activeProduct;
var prefixBlob;
var volumeSlider;
var awsCreds = new AWS.CognitoIdentityCredentials({
	IdentityPoolId: 'us-east-2:3d2538af-9a51-40f1-a1e0-58263df824bd'
});
var awsConfig = new AWS.Config({
	credentials: awsCreds,
	region: 'us-east-2'
});
AWS.config.update(awsConfig);

// Listening for the mouse and touch events
for (const button of buttons) {
	button.addEventListener("mousedown", pressingDown, false);
	button.addEventListener("mouseup", notPressingDown, false);

	button.addEventListener("touchstart", pressingDown, false);
	button.addEventListener("touchend", notPressingDown, false);
}    

document.oncontextmenu = function () { return false; };

window.onload = function () {
	// set up volume slider
	volumeSlider = $("#volume-slider").slider();

	// Construct recorder
	recorder = new MicRecorder({
		bitRate: 128
	});

	// Attempt a recording to prompt user to allow audio
	recorder.start().then(() => {
		// User allowed audio, stop recording
		recorder.stop();
	}).catch((e) => {
		// Unable to record audio
		// TODO: prompt user somehow
		console.error(e);
	});

	// Fetch prefix audio file
	fetch(window.staticFilepath + "audio/chime.mp3")
		.then(function(response) {
			return response.blob();
		}).then(function(blob) {
			prefixBlob = blob;
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
	document.getElementById(e.target.id + "_label").textContent = "GETTING READY ⏳";
	recorder.start().then(function() {
		document.getElementById(e.target.id + "_label").textContent = "RECORDING 🎙️";
	});
}

function notPressingDown(e) {
	activeProduct = e.target;
	document.getElementById(e.target.id + "_label").textContent = "SENDING 📡";

	// Stop recording
	var stopFunction = function() {
		recorder.stop().getMp3().then(function ([buffer, blob]) {
			// Append prefix to blob
			var finalBlob = new Blob([prefixBlob, blob], { type: blob.type });

			// Upload to S3
			var uuid = generateUUID();
			// bam_msg_ prefixed objects are cleaned up after 1 day
			filename = "bam_msg_" + uuid + ".mp3";
			var upload = new AWS.S3.ManagedUpload({
				params: {
					Bucket: "bose-audio-messages-demo",
					Key: filename,
					Body: finalBlob,
					ACL: "public-read"
				}
			});

			upload.promise().then(
				function (data) {
					console.log("upload success! URL: ", data.Location);
					console.log("product to sent to: ", activeProduct.id);

					var playUrl = window.serverRoot + "send";

					var message = {
						"origin": "BAM Web App",
						"key": filename,
						"target_product": activeProduct.id,
						"vendor": activeProduct.dataset.vendor,
						"url": data.Location,
						"volume": volumeSlider.slider('getValue')
					}
					console.log(message);
					fetch(playUrl, {
						method: 'POST',
						body: JSON.stringify(message),
						headers: new Headers({
							'content-type': 'application/json'
						})

					}).then(() => {
						document.getElementById(activeProduct.id + "_label").textContent = "SENT! 🎉";

						setTimeout(() => {
							document.getElementById(activeProduct.id + "_label").textContent = document.getElementById(activeProduct.id + "_label").dataset.originalValue;
						}, 5000);
					});

				},
				function (err) {
					console.log("There was an error uploading the mesage: ", err.message);
				}
			);
		}).catch(function (e) {
			// Unable to get MP3 audio
			// TODO: prompt user somehow
			console.error(e);
		});
	}

	// Stop after 500ms buffer
	setTimeout(stopFunction, 500);
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
