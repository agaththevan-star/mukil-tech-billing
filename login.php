<?php
/**
 * MUKIL TECH - Login Page
 */

define('SKIP_AUTO_LOGIN', true);
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: ' . baseUrl('admin/dashboard.php'));
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Basic rate limiting or CSRF could go here, but let's keep it simple
    // Simple session based rate limiter
    if (empty($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['login_last_attempt'] = 0;
    }
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // If too many attempts within short time, throttle
    if ($_SESSION['login_attempts'] >= 6 && (time() - ($_SESSION['login_last_attempt'] ?? 0)) < 300) {
        $error = 'Too many login attempts. Please try again later.';
    }
    
    if (empty($username) || empty($password)) {
        $error = 'Please enter both username and password.';
    } else {
        $db = getDB();
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ? AND status = 'active'");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password'])) {
            // Login successful, set session variables
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['user_id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['email'] = $user['email'];
            // reset rate limiter on success
            $_SESSION['login_attempts'] = 0;
            $_SESSION['login_last_attempt'] = time();
            
            // Redirect to dashboard
            header('Location: ' . baseUrl('admin/dashboard.php'));
            exit;
        } else {
            $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
            $_SESSION['login_last_attempt'] = time();
            $error = 'Invalid username or password, or account inactive.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - MUKIL TECH</title>
    <link rel="stylesheet" href="<?= baseUrl('assets/css/style.css') ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            background-color: #f1f5f9;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .login-container {
            background: #ffffff;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            width: 100%;
            max-width: 400px;
        }
        .login-logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        .login-logo img {
            max-width: 150px;
            height: auto;
        }
        .login-title {
            text-align: center;
            color: #1e293b;
            margin-top: 0;
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
        }
        .form-group {
            margin-bottom: 1.25rem;
        }
        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            color: #475569;
            font-weight: 500;
        }
        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 1rem;
            box-sizing: border-box;
        }
        .form-control:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        .btn-primary {
            background-color: #2563eb;
            color: white;
            border: none;
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: background-color 0.2s;
        }
        .btn-primary:hover {
            background-color: #1d4ed8;
        }
        .alert-danger {
            background-color: #fee2e2;
            color: #991b1b;
            padding: 0.75rem;
            border-radius: 6px;
            margin-bottom: 1rem;
            font-size: 0.875rem;
            text-align: center;
        }
    </style>
</head>
<body>

<div class="login-container">
    <div class="login-logo">
        <img src="<?= baseUrl('assets/images/mukil-tech-logo.png') ?>" alt="MUKIL TECH Logo">
    </div>
    
    <h2 class="login-title">Sign In</h2>
    
    <?php if ($error): ?>
        <div class="alert-danger"><?= e($error) ?></div>
    <?php endif; ?>
    
    <form method="POST" action="<?= baseUrl('login.php') ?>">
        <div class="form-group">
            <label class="form-label" for="username">Username</label>
            <input type="text" id="username" name="username" class="form-control" required autofocus>
        </div>
        
        <div class="form-group">
            <label class="form-label" for="password">Password</label>
            <input type="password" id="password" name="password" class="form-control" required>
        </div>
        
        <button type="submit" class="btn-primary">Log In</button>
    </form>
    
    <div style="text-align: center; margin-top: 1.5rem; font-size: 0.875rem; color: #64748b;">
        &copy; <?= date('Y') ?> MUKIL TECH
    </div>
</div>

</body>
</html>
