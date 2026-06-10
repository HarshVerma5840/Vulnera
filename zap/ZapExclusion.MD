# ZAP Scan Optimization: Exclusion List

To drastically improve scan times and avoid fuzzing endpoints that cannot be dynamically exploited, the following file types, directories, and third-party domains should be excluded from both the ZAP Spider and Active Scanner.

> [!NOTE]
> Per your request, document exports (e.g., `.pdf`, `.csv`, `.docx`) have been intentionally left **out** of the exclusion list. They will continue to be scanned in case the application has backend parsing logic susceptible to injection attacks.

## 1. File Extensions (Static Assets)

These files are statically served to the client and contain no server-side execution logic that can be manipulated via HTTP parameters.

| Category | Extensions | Reason for Exclusion |
| :--- | :--- | :--- |
| **Stylesheets** | `\.css$`, `\.scss$`, `\.less$` | Static styling. Cannot execute server-side code. |
| **Fonts** | `\.woff$`, `\.woff2$`, `\.ttf$`, `\.eot$`, `\.otf$` | Static typography files. |
| **Images** | `\.png$`, `\.jpg$`, `\.jpeg$`, `\.gif$`, `\.svg$`, `\.ico$`, `\.webp$`, `\.bmp$` | Static images. While malicious image uploads are a vector, simply *fetching* an existing image with DAST payloads is a waste of time. |
| **Media** | `\.mp4$`, `\.mp3$`, `\.wav$`, `\.webm$`, `\.avi$` | Static audio/video binaries. |
| **Source Maps** | `\.js\.map$`, `\.css\.map$` | Used purely by browser dev tools for mapping minified code back to original source. |

## 2. Directories (Client-Side Dependencies)

These directories contain third-party libraries. Dynamic scanning (DAST) is the wrong tool for these; they should be analyzed via Software Composition Analysis (SCA) to check for known vulnerable versions against CVE databases.

| Directory Pattern | Description |
| :--- | :--- |
| `.*/node_modules/.*` | NPM packages and JavaScript dependencies. |
| `.*/vendor/.*` | Common directory for PHP (Composer), Ruby, or Go dependencies. |
| `.*/bower_components/.*` | Legacy frontend package dependencies. |
| `.*/\.venv/.*` | Python virtual environments. |

## 3. Out-of-Scope Third-Party Domains

If the target web application imports scripts from external domains, the ZAP Spider might attempt to crawl and attack those external services. This is out of scope and wastes significant time.

| Domain Pattern | Service |
| :--- | :--- |
| `.*\.google-analytics\.com` | Google Analytics |
| `.*\.googletagmanager\.com` | Google Tag Manager |
| `.*\.facebook\.net` | Facebook Tracking/Pixels |
| `.*\.hotjar\.com` | Hotjar UX Tracking |
| `.*\.stripe\.com` | Stripe Payment Gateway |

---

### Implementation Note for Later
When we are ready to implement this in `scanner.py`, we will use the `self.zap.spider.exclude_from_scan(regex)` and `self.zap.ascan.exclude_from_scan(regex)` API methods, passing in the compiled Regular Expressions of the items in this table.
