from ignite import DisplayArtwork, client

for artwork in DisplayArtwork.objects:
    client.collections["artworksearch"].documents.create({
        'name': artwork.name,
        'country': artwork.country,
        'artname': artwork.artname,
        'medium': artwork.medium,
        'caption': artwork.caption
    })
