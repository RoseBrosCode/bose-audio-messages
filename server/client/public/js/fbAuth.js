window.fbAsyncInit = function() {
	FB.init({
		appId            : '210242747075512',
		autoLogAppEvents : true,
		xfbml            : true,
		version          : 'v10.0'
	});
	FB.Event.subscribe('auth.statusChange', onFbStatusChange);
};

function onFbStatusChange(response) {
	if (response.status === 'connected') {
		// Signed in to BAM and Facebook.
		fetch(fbAuthURL, {
			method: 'POST',
			body: JSON.stringify({
				"fb_token": response.authResponse.accessToken,
				"fb_user_id": response.authResponse.userID
		}),
			headers: new Headers({
					'content-type': 'application/json'
			})
		}).then(resp => {
			if (resp.redirected) {
					window.location.replace(resp.url);
			}
		}).catch(function(err) {
			// TODO consider informing the user
			console.log(err);
		});
	} else {
		// The person is not logged into your webpage or we are unable to tell.
		console.log("facebook error:", response);
	}    
}
