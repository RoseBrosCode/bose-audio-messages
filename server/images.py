PRODUCT_TYPE_IMAGE_PREFIX_MAP = {
    'Bose Home Speaker 300': 'flipper',
    'Bose Home Speaker 450': 'eddie-club',
    'Bose Home Speaker 500': 'eddie-black',
    'Bose Smart Soundbar 300': 'sandiego',
    'Bose Soundbar 500': 'professor',
    'Bose Soundbar 700': 'g-c',
    'Bose Portable Home Speaker': 'taylor'
}

IMAGE_SUFFIXES = [
    ".png",
    "-getting-ready.png",
    "-recording.png",
    "-sending.png",
    "-sent.png"
]

def get_product_image_name_and_filenames(product_type):
    image_name = PRODUCT_TYPE_IMAGE_PREFIX_MAP[product_type]
    image_filenames = [image_name + suffix for suffix in IMAGE_SUFFIXES]
    return image_name, image_filenames
