# WordPress File Guard

Dead simple file and directory protection for WordPress plugins. Protects upload directories with .htaccess rules, index files, and verifies protection is working.

## Install

```bash
composer require arraypress/wp-file-guard
```

## Basic Usage

```php
use ArrayPress\FileGuard\Protector;

// Create protector for your plugin
$protector = new Protector( 'myplugin' );

// Protect the upload directory
$protector->protect();

// Check if protected
if ( $protector->is_protected() ) {
	echo "Files are protected!";
}

// Get upload paths
$path = $protector->get_upload_path();  // /wp-content/uploads/myplugin
$url  = $protector->get_upload_url();    // https://site.com/wp-content/uploads/myplugin
```

## Real Example (Your SugarCart Code)

### Before
```php
function create_protection_files( $force = false ) {
	// 100+ lines of protection code...
}
```

### After
```php
use ArrayPress\FileGuard\Protector;

class SugarCart {
	private Protector $protector;

	public function __construct() {
		// Allow previews of images and audio samples
		$this->protector = new Protector(
			'sugarcart',
			[ 'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'mp3', 'ogg' ],
			true // Use year/month folders
		);

		// Auto-protect on admin_init
		$this->protector->schedule_protection();

		// Auto-organize uploads for products
		$this->protector->setup_upload_filter( 'sc_product' );

		// Or for admin pages
		$this->protector->setup_upload_filter( 'admin:sugarcart-files' );
	}

	public function get_upload_dir( $dated = false ): string {
		return $this->protector->get_upload_path( $dated );
	}

	public function get_upload_url( $dated = false ): string {
		return $this->protector->get_upload_url( $dated );
	}

	public function is_protected(): bool {
		return $this->protector->is_protected();
	}
	
}
```

## Features

### Directory Protection
Creates three layers of protection:
- `.htaccess` - Apache rules (deny all, allow specific types)
- `index.php` - PHP silence file
- `index.html` - Empty HTML file

### Custom Upload Directories
Automatically organizes uploads:
```
/wp-content/uploads/
    /myplugin/
        /2024/
            /01/
                file.pdf (protected)
                preview.jpg (allowed)
```

### Protection Testing
Actually tests if files are protected:
```php
// Tests by creating a temporary file and trying to access it
if ( $protector->is_protected() ) {
	// Files are actually protected (not just .htaccess exists)
}
```

### Flexible Upload Filtering

The `setup_upload_filter()` method is super flexible:

```php
// For post types
$protector->setup_upload_filter( 'product' );
$protector->setup_upload_filter( [ 'product', 'download' ] );

// For admin pages
$protector->setup_upload_filter( 'admin:myplugin-files' );

// Custom logic with callback
$protector->setup_upload_filter( function () {
	// Check for specific page and action
	return is_admin()
	       && isset( $_GET['page'] ) && $_GET['page'] === 'myplugin-files'
	       && isset( $_GET['action'] ) && $_GET['action'] === 'add';
} );

// Complex conditions
$protector->setup_upload_filter( function () {
	// Multiple conditions
	if ( isset( $_GET['special_upload'] ) ) {
		return true;
	}
	if ( current_user_can( 'manage_downloads' ) && is_admin() ) {
		return true;
	}

	return false;
} );
```

## Complete Example

```php
use ArrayPress\FileGuard\Protector;

class DownloadPlugin {
	private Protector $protector;

	public function __construct() {
		// Setup protection
		$this->protector = new Protector(
			'downloads',                              // Directory name
			[ 'jpg', 'png', 'mp3' ],                    // Allow previews
			true                                       // Use dated folders
		);

		// Hook into WordPress
		add_action( 'init', [ $this, 'init' ] );
	}

	public function init() {
		// Protect files on admin screens
		$this->protector->schedule_protection();

		// Organize uploads for download post type
		$this->protector->setup_upload_filter( 'download' );

		// Also organize uploads on settings page
		$this->protector->setup_upload_filter( 'admin:download-settings' );

		// Or use custom logic
		$this->protector->setup_upload_filter( function () {
			return isset( $_GET['download_upload'] ) && $_GET['download_upload'] === '1';
		} );
	}

	public function activate() {
		// Force protection on activation
		$this->protector->protect( true );
	}

	public function deactivate() {
		// Optional: Remove protection files
		$this->protector->unprotect();
	}

	public function get_status(): array {
		return [
			'protected' => $this->protector->is_protected(),
			'path'      => $this->protector->get_upload_path(),
			'url'       => $this->protector->get_upload_url()
		];
	}
}

// On plugin activation
register_activation_hook( __FILE__, function () {
	$plugin = new DownloadPlugin();
	$plugin->activate();
} );
```

## Methods

```php
// Create protection files
$protector->protect( $force = false );

// Check if protected
$is_protected = $protector->is_protected( $force = false );

// Get paths
$path = $protector->get_upload_path( $dated = false );
$url  = $protector->get_upload_url( $dated = false );

// Setup automatic protection
$protector->schedule_protection( 'admin_init' );

// Filter uploads (flexible)
$protector->setup_upload_filter( 'post_type' );                // Post type
$protector->setup_upload_filter( 'admin:page_slug' );          // Admin page
$protector->setup_upload_filter( function () {
	return true;
} ); // Custom

// Manual upload filter
add_filter( 'upload_dir', [ $protector, 'filter_upload_dir' ] );

// Get Nginx rules
$nginx_rules = $protector->get_nginx_rules();

// Remove protection
$protector->unprotect();
```

## Configuration

```php
// Basic - just protect files
$protector = new Protector( 'myplugin' );

// Allow certain file types for preview
$protector = new Protector(
	'myplugin',
	[ 'jpg', 'jpeg', 'png', 'gif', 'mp3', 'ogg' ]
);

// Don't use dated folders
$protector = new Protector(
	'myplugin',
	[ 'jpg', 'png' ],
	false  // Everything goes in /myplugin/ directly
);
```

## Server Configuration

### Apache
Works automatically with .htaccess files.

### Nginx
Get the configuration rules:
```php
$nginx_rules = $protector->get_nginx_rules();
// Add to your nginx config:
// location ~ ^/myplugin/ {
//     deny all;
//     location ~ \.(jpg|jpeg|png|gif)$ {
//         allow all;
//     }
// }
```

### IIS
Index files provide basic protection. Configure IIS web.config for full protection.

## How It Works

1. **Creates protection files** - .htaccess, index.php, index.html
2. **Tests protection** - Creates test file, tries to access via HTTP
3. **Caches results** - Uses transients to avoid repeated checks
4. **Handles subdirectories** - Protects year/month folders automatically
5. **Filters uploads** - Organizes uploads based on conditions

## Why Use This?

- **Simple** - One class, clear methods
- **Flexible** - Handles post types, admin pages, or custom logic
- **Tested** - Actually verifies protection works
- **Smart** - Caches results, handles subdirectories
- **WordPress Native** - Uses WordPress functions properly

## Requirements

- PHP 7.4 or later
- WordPress 5.0 or later

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPL-2.0-or-later License.

## Support

- [Documentation](https://github.com/arraypress/wp-file-guard)
- [Issue Tracker](https://github.com/arraypress/wp-file-guard/issues)