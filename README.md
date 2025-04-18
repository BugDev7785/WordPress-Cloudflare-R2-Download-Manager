![image_alt](https://github.com/BugDev7785/WordPress-Cloudflare-R2-Download-Manager/blob/main/Cloudflare%20R2%20Manager.png?raw=true)
# Cloudflare R2 Manager for WordPress

A powerful WordPress plugin that integrates Cloudflare R2 object storage with your WordPress site, allowing seamless file management and delivery through Cloudflare's global network.

## Features

- **URL Rewriting**: Serves media files directly from Cloudflare R2, improving load times and reducing origin server load
- **File Management**: Browse, download, and manage files in your R2 bucket directly from WordPress admin
- **Role-based Access Control**: Control which WordPress user roles can access files from your R2 bucket
- **Direct File Uploads**: Upload files to R2 directly from the WordPress admin interface
- **Secure Downloads**: Generate secure, temporary download links for your R2 files
- **Real-time Progress**: Modern upload interface with real-time progress tracking
- **Secure Authentication**: Uses industry-standard SigV4 authentication for R2 compatibility
- **CSV Export**: Export your complete bucket file list to CSV format for reporting and analysis
- **Pagination Controls**: Navigate through large buckets with easy-to-use pagination
- **Custom URL Prefix**: Configure your own download URL prefix for better security
- **Visual Notifications**: User-friendly notifications for all operations

## Installation

1. Upload the plugin files to your `/wp-content/plugins/` directory or install via the WordPress plugin screen
2. Activate the plugin through the WordPress 'Plugins' menu
3. Navigate to the Cloudflare R2 menu in your admin dashboard to configure the plugin

## Configuration

1. In your WordPress admin area, go to Cloudflare R2 > Settings
2. Enter your Cloudflare R2 credentials:
   - Account ID
   - Access Key ID
   - Secret Access Key
   - Bucket Name
   - Download URL Prefix (optional)
3. Save your settings
4. If you change the Download URL Prefix, remember to visit Settings > Permalinks and save to update rewrite rules

## Access Control

1. Go to Cloudflare R2 > Access Control
2. Select which user roles can download files from your R2 bucket
3. Only users with the selected roles will be able to access protected R2 files

## Usage

### Media Library Integration
Once configured, all files uploaded to your WordPress media library will be automatically stored in your Cloudflare R2 bucket.

### Bucket File Management
View and manage all files in your R2 bucket from the Cloudflare R2 > Bucket List page. Features include:
- Browsing files with pagination controls
- Searching for specific files
- Viewing file details (size, type, last modified)
- Copying secure download links
- Directly downloading files
- Exporting bucket list to CSV

### Direct File Uploads
Use the upload form on the Settings page to directly upload files to your R2 bucket without adding them to the media library.

## Requirements

- WordPress 5.0 or higher
- PHP 7.0 or higher
- cURL PHP extension
- Cloudflare R2 account with API credentials

## Support

For questions or issues, please contact the plugin author.

## Changelog

### 1.4
- Added CSV export functionality for bucket lists
- Improved pagination controls for navigating large buckets
- Added custom download URL prefix configuration
- Enhanced notification system for user operations
- UI improvements for better user experience
- Performance optimizations for large file operations

---

Made with ♥ for WordPress and Cloudflare R2
