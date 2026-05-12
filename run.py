"""USX Migrator Assistant — Entry point."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    print("\n  USX Migrator Assistant")
    print("  http://localhost:5000\n")
    app.run(debug=True, port=5000)
