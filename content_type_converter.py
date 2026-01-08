import json

class ContentTypeConverter:
    """
    Converts request body data between different content types.
    Supports conversions between:
    - application/json
    - application/x-www-form-urlencoded
    - multipart/form-data
    """
    
    @staticmethod
    def convert(body_data, from_type, to_type):
        """
        Convert body data from one content type to another.
        
        Args:
            body_data: The body data in the original format (dict or string)
            from_type: Source content type (e.g., "application/json")
            to_type: Target content type (e.g., "application/x-www-form-urlencoded")
            
        Returns:
            Converted body data in the target format
        """
        if from_type == to_type:
            return body_data
        
        # Normalize content types
        from_type = ContentTypeConverter._normalize_content_type(from_type)
        to_type = ContentTypeConverter._normalize_content_type(to_type)
        
        # Convert to intermediate dict format
        intermediate = ContentTypeConverter._to_dict(body_data, from_type)
        
        # Convert from intermediate dict to target format
        return ContentTypeConverter._from_dict(intermediate, to_type)
    
    @staticmethod
    def _normalize_content_type(content_type):
        """Normalize content type string to standard format."""
        if content_type is None:
            return None
        # Remove charset and other parameters
        base_type = content_type.split(';')[0].strip().lower()
        return base_type
    
    @staticmethod
    def _to_dict(body_data, content_type):
        """Convert body data to dictionary format."""
        if body_data is None:
            return {}
        
        if isinstance(body_data, dict):
            return body_data
        
        if content_type == "application/json":
            if isinstance(body_data, str):
                return json.loads(body_data)
            return body_data
        
        elif content_type == "application/x-www-form-urlencoded":
            if isinstance(body_data, str):
                result = {}
                for pair in body_data.split("&"):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        result[ContentTypeConverter._url_decode(key)] = ContentTypeConverter._url_decode(value)
                return result
            return body_data
        
        elif content_type == "multipart/form-data":
            # Multipart data is already in dict format from RequestTree
            if isinstance(body_data, dict):
                return body_data
            return {}
        
        return {}
    
    @staticmethod
    def _from_dict(data_dict, content_type):
        """Convert dictionary to target content type format."""
        # All formats use dict internally, actual conversion happens in parsers
        return data_dict
    
    @staticmethod
    def _url_decode(s):
        """URL decode a string."""
        encoded = str(s)
        result = ""
        i = 0
        while i < len(encoded):
            c = encoded[i]
            if c == '%':
                if i + 2 < len(encoded):
                    url_value = int(encoded[i+1:i+3], 16)
                    result += chr(url_value)
                    i += 3
                else:
                    result += c
                    i += 1
            elif c == '+':
                result += ' '
                i += 1
            else:
                result += c
                i += 1
        return result
    
    @staticmethod
    def get_supported_conversions():
        """Return list of supported content type conversions."""
        return [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data"
        ]
