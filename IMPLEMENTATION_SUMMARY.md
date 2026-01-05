# Advanced Copy Feature - Implementation Summary

## Overview
Successfully implemented the "Advanced..." copy feature as requested in the issue. This feature allows users to copy HTTP requests with a different content-type than the original, with automatic body conversion and header updates.

## What Was Implemented

### 1. Core Functionality
- **Content-Type Converter** (`content_type_converter.py`): A standalone module that handles conversion between different content-types
  - Supports JSON ↔ x-www-form-urlencoded conversion
  - Properly handles URL encoding/decoding
  - Includes bounds checking to prevent errors

### 2. Enhanced RequestTree
- Added `target_content_type` parameter to RequestTree constructor
- Automatic content-type conversion when target differs from source
- Automatic Content-Type header updates

### 3. UI Enhancement
- Added "Advanced..." menu item in the "more..." submenu
- Interactive dialog for selecting target content-type and output language
- Clear error messages for invalid input

### 4. Code Generation
- Works with both JavaScript and Python output
- Generated code respects the new content-type
- Properly uses JSON.stringify or form encoding functions as needed

## Testing

### Test Coverage (34 tests total)
1. **Content-Type Converter Tests** (8 tests)
   - JSON to form conversion
   - Form to JSON conversion  
   - URL encoding/decoding
   - Content-type normalization

2. **RequestTree Tests** (6 tests)
   - Basic parsing tests (existing)
   - Content-type conversion tests (3 new)

3. **Advanced Copy Integration Tests** (4 tests)
   - JSON to form with JavaScript output
   - Form to JSON with JavaScript output
   - JSON to form with Python output
   - Form to JSON with Python output

4. **Other Tests** (16 tests)
   - Header filtering, JavaScript parser, integration tests (existing)

### All Tests Passing ✓
```
Ran 34 tests
OK
```

## Security

### CodeQL Analysis: PASSED ✓
- 0 vulnerabilities found
- Added bounds checking for URL decoding to prevent IndexError
- No security issues introduced

## Documentation

### Updated Files
1. **README.md**: Added section explaining the Advanced Copy feature
2. **ADVANCED_COPY_EXAMPLES.md**: Comprehensive usage examples
3. **IMPLEMENTATION_SUMMARY.md**: This file

## Usage

Users can now:
1. Right-click a request in Burp Suite
2. Navigate to: `Extensions > Copy Request > more > Advanced...`
3. Enter format: `<content-type-number>,<language>`
   - Example: `1,js` for JSON + JavaScript
   - Example: `2,python` for form-encoded + Python

The extension will:
- Convert the body to the target content-type
- Update the Content-Type header
- Generate code in the selected language

## Files Changed

```
ADVANCED_COPY_EXAMPLES.md            | 101 ++++++
README.md                            |  26 +++
content_type_converter.py            | 113 +++++++
main.py                              |  68 ++++
request_tree.py                      |  65 +++
tests/test_advanced_copy.py          | 179 ++++++++++
tests/test_content_type_converter.py | 102 ++++++
tests/test_request_tree.py           |  46 +++
tests/test_runner.py                 |   2 +
```

Total: 9 files changed, 695 insertions(+), 7 deletions(-)

## Considerations & Notes

### Per Issue Requirements
✓ Added "Advanced..." field in "Copy as" context menu
✓ Includes option to copy request as different content-type
✓ Changes Content-Type header accordingly (per comment)

### Design Decisions
1. **Dialog Format**: Simple `number,language` format is easy to type and understand
2. **Supported Conversions**: Started with JSON ↔ form-urlencoded as these are the most common
3. **Code Structure**: Kept conversion logic separate for easy extension to other content-types
4. **Error Handling**: Graceful handling of invalid input with clear error messages

### Future Enhancements (Not in Scope)
- Support for multipart/form-data conversion
- Support for XML content-type
- Preset conversion configurations
- UI with dropdown selections instead of text input

## Testing in Burp Suite

The implementation follows Burp Suite extension patterns:
- Uses Jython-compatible code
- Integrates with existing menu structure
- Maintains compatibility with existing features
- No breaking changes to existing functionality

Note: Manual testing in actual Burp Suite environment is recommended to verify UI integration, though automated tests cover all logic.
