const CACHE_NAME = 'countdown-app-cache-v1';
const urlsToCache = [
  '/',
  '/style.css',
  // Hier könnte man noch das JavaScript cachen, aber es ist in der HTML-Datei
];

// Installation: Cache öffnen und die grundlegenden Dateien hinzufügen
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Cache geöffnet');
        return cache.addAll(urlsToCache);
      })
  );
});

// Fetch: Anfragen abfangen und aus dem Cache bedienen
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Wenn die Anfrage im Cache ist, gib sie zurück.
        if (response) {
          return response;
        }
        // Ansonsten normal über das Netzwerk anfragen.
        return fetch(event.request);
      }
    )
  );
});
