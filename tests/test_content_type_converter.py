import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from content_type_converter import ContentTypeConverter

class TestContentTypeConverter(unittest.TestCase):
    
    def test_json_to_urlencoded(self):
        """Test conversion from JSON to x-www-form-urlencoded."""
        json_data = {
            "username": "testuser",
            "password": "testpass"
        }
        
        result = ContentTypeConverter.convert(
            json_data,
            "application/json",
            "application/x-www-form-urlencoded"
        )
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result["username"], "testuser")
        self.assertEqual(result["password"], "testpass")
    
    def test_urlencoded_to_json(self):
        """Test conversion from x-www-form-urlencoded to JSON."""
        urlencoded_data = {
            "email": "test@example.com",
            "age": "25"
        }
        
        result = ContentTypeConverter.convert(
            urlencoded_data,
            "application/x-www-form-urlencoded",
            "application/json"
        )
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result["email"], "test@example.com")
        self.assertEqual(result["age"], "25")
    
    def test_same_type_no_conversion(self):
        """Test that no conversion occurs when types are the same."""
        data = {"key": "value"}
        
        result = ContentTypeConverter.convert(
            data,
            "application/json",
            "application/json"
        )
        
        self.assertEqual(result, data)
    
    def test_url_decode_with_encoded_chars(self):
        """Test URL decoding with percent-encoded characters."""
        encoded = "hello%20world%21"
        decoded = ContentTypeConverter._url_decode(encoded)
        self.assertEqual(decoded, "hello world!")
    
    def test_url_decode_with_plus(self):
        """Test URL decoding with plus signs."""
        encoded = "hello+world"
        decoded = ContentTypeConverter._url_decode(encoded)
        self.assertEqual(decoded, "hello world")
    
    def test_normalize_content_type(self):
        """Test content type normalization."""
        ct_with_charset = "application/json; charset=utf-8"
        normalized = ContentTypeConverter._normalize_content_type(ct_with_charset)
        self.assertEqual(normalized, "application/json")
    
    def test_get_supported_conversions(self):
        """Test getting supported conversion types."""
        supported = ContentTypeConverter.get_supported_conversions()
        self.assertIsInstance(supported, list)
        self.assertIn("application/json", supported)
        self.assertIn("application/x-www-form-urlencoded", supported)
        self.assertIn("multipart/form-data", supported)
    
    def test_nested_json_to_urlencoded(self):
        """Test conversion with nested JSON (should flatten or handle gracefully)."""
        json_data = {
            "user": {
                "name": "test",
                "id": 123
            }
        }
        
        # This should handle nested structures somehow
        result = ContentTypeConverter.convert(
            json_data,
            "application/json",
            "application/x-www-form-urlencoded"
        )
        
        # Result should still be a dict (nested structure preserved in this simple implementation)
        self.assertIsInstance(result, dict)

if __name__ == '__main__':
    unittest.main()
