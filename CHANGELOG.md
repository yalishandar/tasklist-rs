# Changelog

## [0.3.0] - 2025-05-05

### Fixed
- Fixed incorrect VerQueryValueW API usage in `get_proc_file_info()` 
  - Corrected parameter types and error handling
  - Added proper pointer type conversions
- Resolved memory safety issues in process parameter reading
  - Improved wide string conversion safety
  - Added buffer boundary checks

### Changed
- Modified `Tasklist::new()` to return `Result<Tasklist, String>`
  - Added RAII pattern for handle management
  - Improved error messages
  - Now properly closes handles on failure

### Added
- Added architecture detection for WOW64 processes
- Added file version info extraction capabilities