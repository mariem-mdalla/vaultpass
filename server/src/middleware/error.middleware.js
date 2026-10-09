export function errorMiddleware(err, req, res, next) {
  // Log the full error so we can see it in our terminal
  console.error(err.stack);

  // Use the error's status code, or default to 500 (server error)
  const status = err.status || 500;

  res.status(status).json({
    // In production → hide details from hackers
    // In development → show real error so we can debug
    message: process.env.NODE_ENV === "production"
      ? "Something went wrong."
      : err.message,
  });
}