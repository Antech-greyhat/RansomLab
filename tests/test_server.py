import unittest

from ransomlab.server import BoundedRequest


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def execute(self, chunks, headers=()):
        replies, delivered = [], []

        async def inner(scope, receive, send):
            delivered.append(await receive())
            await send({"type": "http.response.start", "status": 200, "headers": []})

        iterator = iter(chunks)

        async def receive():
            return next(iterator)

        async def send(message):
            replies.append(message)

        await BoundedRequest(inner, max_bytes=4)({"type": "http", "headers": list(headers)}, receive, send)
        return replies, delivered

    async def test_body_is_bounded_before_wsgi_buffering(self):
        replies, delivered = await self.execute([{"type": "http.request", "body": b"123", "more_body": True},
                                                 {"type": "http.request", "body": b"45", "more_body": False}])
        self.assertEqual(replies[0]["status"], 413)
        self.assertEqual(delivered, [])

    async def test_valid_chunked_body_is_delivered_once(self):
        replies, delivered = await self.execute([{"type": "http.request", "body": b"12", "more_body": True},
                                                 {"type": "http.request", "body": b"34", "more_body": False}])
        self.assertEqual(replies[0]["status"], 200)
        self.assertEqual(delivered[0]["body"], b"1234")

    async def test_excess_headers_rejected_without_body_read(self):
        replies, delivered = await self.execute([], [(b"x", b"y")] * 65)
        self.assertEqual(replies[0]["status"], 431)
        self.assertEqual(delivered, [])


if __name__ == "__main__":
    unittest.main()
