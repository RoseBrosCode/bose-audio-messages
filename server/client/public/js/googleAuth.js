function onGoogleFailure(error){
	console.log("google failure")
	console.log(error);
	// TODO consider informing the user
}

function googleInit() {
	gapi.load('auth2', function() {
			gapi.auth2.init({}).then(function(auth2) {
				var signin_needed = document.body.contains(document.getElementById('googleBtn'));
				console.log('is signin needed?', signin_needed);  
				if (signin_needed) {
					element = document.getElementById('googleBtn');
					auth2.attachClickHandler(element, {
							scope: 'profile email',
							prompt: 'select_account'
					}, onGoogleSignIn, onGoogleFailure);
				}
			}, onGoogleFailure);
	});
}

function onGoogleSignIn(googleUser) {
	// Getting the google ID token:
	var id_token = googleUser.getAuthResponse().id_token;
	console.log("ID Token: " + id_token);
	fetch(googleAuthURL, {
		method: 'POST',
		body: JSON.stringify({
				"g_token": id_token
		}),
		headers: new Headers({
				'content-type': 'application/json'
		})
	}).then(resp => {
		if (resp.redirected) {
				window.location.replace(resp.url);
		}
	}).catch(function(err) {
		console.log(err);
		// TODO consider informing the user
	});
}
