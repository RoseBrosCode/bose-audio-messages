# Genericization Plan
This document outlines the steps planned to convert BAM from a Bose-only application to one that supports Bose and Sonos.

# TODO:
## Server Main Application (`main.py`)
### Modifications
#### `play_msg()` Route Handler
Evolve all token-checking logic to account for multiple speaker vendors.

When needed, redirect to `/manage` instead of `/login/bose`.

Calls to send_audio_notification must be updated to include the `product_vendor` argument.

## Client Template `app.html`
### Modifications
Update speaker visual presentation to move away from current image-based system and to a icon-based system.

Users will tap the icon as they tapped the image before. Product name will now be ABOVE the icon, and the product name will update to hold the status images (instead of them being in the image).

Product vendor will need to be added as an attribute to the product image

## Client Template `base.html`
### Modifications
In the footer, change the Bose Unlink link to a more generic Manage Linked Accounts link and have it link to `/manage` instead of `/logout/bose`.

## Client Template `bose-link.html` --> `manage.html`
Note the name change of this template.

### Modifications
Update this to provide link options to both Bose and Sonos, and also to provide unlink options when an account is linked.

## Client `main.js`
### Modifications
Wherever images are swapped out to update status, make updates to enable new UX outlined in the `app.html` modifications listed above.

Also, need to update the audio notification message POST to include vendor name. 

# DONE
## Naming and Copy
BAM originally stood for Bose Audio Messages. This will be genericized to Brief Audio Messages throughout.

## Server Constants (`constants.py`)
### Additions
`BOSE_VENDOR_ID = "bose"`
`SONOS_VENDOR_ID = "sonos"`

No modifications or deletions.

## Server User Model (`user.py`)
### Additions
The following properties will be added: 
- `self.bose_encrypted_refresh_token`
- `self.bose_encrypted_access_token`
- `self.sonos_encrypted_refresh_token`
- `self.sonos_encrypted_access_token`

### Modifications
The following methods will be changed:
#### `__init__`
New Arguments:
- `self.bose_encrypted_refresh_token=None`
- `self.bose_encrypted_access_token=None`
- `sonos_encrypted_refresh_token=None`
- `sonos_encrypted_access_token=None`

Logic Changes:
Set the new properties appropriately based on new/updated arguments and properties.

#### `from_dict`
No additions or changes to arguments

Logic Changes:
Return new properties and address changed property names

#### `get_refresh_token`
New Argument:
- `vendor` - String, either `'bose'` or `'sonos'`. Denotes which speaker vendor's refresh token is desired.

No changes to the existing argument.

Logic Changes:
Add an if statement based on the new `vendor` argument, which determines which refresh token to decrypt and return (either bose or sonos).

#### `set_refresh_token`
New Argument:
- `vendor` - String, either `'bose'` or `'sonos'`. Denotes which speaker vendor's refresh token is desired.

No changes to the existing arguments.

Logic Changes:
Within the "try" block, add an if statement based on the new `vendor` argument, which determines which refresh token to encrypt and set (either bose or sonos).

#### `get_access_token`
Changes essentially the same as `get_refresh_token`.

#### `set_access_token`
Changes essentially the same as `set_refresh_token`.

#### `clear_tokens`
New Argument:
- `vendor` - String, either `'bose'` or `'sonos'`. 

No changes to the existing arguments.

Logic Changes:
Add an if statement based on `vendor` and delete the tokens only for that vendor.

### Methods Not Modified
`load_user`, `get_user_by_username`, `create_user`, `username_exists`, `check_password`, `get_provider_access_token`, `set_provider_access_token`, `set_provider_access_token`, `set_acct_type`, `validate_google_user`, `validate_facebook_user`, `repair_acct_type`

## Server Speaker Client (`switchboard.py` --> `speaker.py`)
Note the name change for this file.

### Additions
None

### Modifications
The following methods will be changed:

#### `refresh_sb_token` --> `get_refreshed_access_token`
Note the name change of this method.

New Argument:
- `vendor` - String, either `'bose'` or `'sonos'`. 

Logic Changes:
Add an if statement based on `vendor` and return a refreshed access token only for that vendor.

#### `get_products`
New Argument:
- `linked_vendors` - Dict, where keys are a String associated with a supported vendor, currently either `'bose'` or `'sonos'`, and the values are a second dict, with keys being a String, either `'refresh'` or `'access'`, and the keys being the appropriate token for that vendor.

Logic Changes:
Add a for loop based on each item in `linked_vendors`, getting the products for each vendor. Return an object that contains all products from both vendors, in a unified schema.

#### `send_audio_notification`
New Argument:
- `vendor` - String, either `'bose'` or `'sonos'`. 
- `refresh_token` - the refresh token associated with the product

Logic Changes:
Add an if statement based on `vendor` that makes the call to the correct vendor's API.

### Methods Not Modified
None - all are modified

## Server Main Application (`main.py`)
### Additions
#### `@app.route('/manage')` and `manage_linked_accounts()` Route Handler
This route will serve a page for the user to link or unlink their Bose and/or Sonos accounts. It will send to the client information about the state of those two account links. This will incorporate logic currently in `sb_login()`.

#### `@app.route('/logout/sonos')` and `sonos_logout()` Route Handler
This will call `clear_tokens('sonos')` on the current user and redirect to `/app` (which would then redirect to `/manage` if needed).

### Deletions
#### ~~`@app.route('/login/bose')` and `sb_login()` Route Handler~~
This will be superceded by the new `/manage` route listed above.

### Modifications
Imports will need to change to reflect updated filenames and methods from external files. Related, method usage throughout will need to be updated based on these updates, and variables in this file will likely need to be renamed appropriately.

#### `landing()` Route Handler
Instead of redirecting to `/login/bose` when a user is authenticated, redirect to the `/app`, which will handle a redirect to `/manage` if needed, for the same reasons described for `register()`.

#### `register()` Route Handler
Already-authenticated users should be redirected to `/app`, which will handle a redirect to `/manage` if needed. This logic change is needed as we should not be overly biased to route users to `/manage` once they have at least one vendor linked.

Upon successful registration, new users should be redirected to `/manage` instead of `/login/bose`.

#### `bam_login()` Route Handler
Already-authenticated users, **and** users that authenticate successfully, should be redirected to `/app`, which will handle a redirect to `/manage` if needed, for the same reasons described in above for `register()`.

#### `google_auth()` Route Handler
Users that authenticate successfully should be redirected to `/app`, which will handle a redirect to `/manage` if needed, for the same reasons described in above for `register()`.

Upon successful registration, new users should be redirected to `/manage` instead of `/login/bose`.

#### `fb_auth()` Route Handler
Users that authenticate successfully should be redirected to `/app`, which will handle a redirect to `/manage` if needed, for the same reasons described in above for `register()`.

Upon successful registration, new users should be redirected to `/manage` instead of `/login/bose`.

#### `sb_logout()` --> `bose_logout()` Route Handler
Note the name change of this method.

The clear tokens method needs the Bose vendor argument.

Once tokens have been cleared, users should be redirected to `/app`, which will handle a redirect to `/manage` if needed, for the same reasons described in above for `register()`.

#### `auth_redirect()` Route Handler
This method will need to use the `state` parameter of the OAuth flow to identify which vendor (Bose or Sonos) is providing the authorization code, and then get and set tokens for the user appropriately.

#### `app_home()` Route Handler
Evolve all token-checking logic to account for multiple speaker vendors.

When needed, redirect to `/manage` instead of `/login/bose`.

The product array should include all products the user has access too, across vendors if needed.

The image name `for` loop can be removed along with use of `image_filenames`.



### Noted Non-Changes
The following are **unchanged**:
- All of the app setup between the imports and the route definitions
- `@app.route('/health')` and handler function
- `@app.route('/logout/bam')` and handler function
- `@app.route('/privacy')` and handler function

## Client `images` Directory
All images with filename starting with `eddie-black-` can be deleted.
