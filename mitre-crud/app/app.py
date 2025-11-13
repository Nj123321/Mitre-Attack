from fastapi import FastAPI
from .routes import domain_base # imports routers

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

# class DomainExtractorMiddleware(BaseHTTPMiddleware):
#     """
#     Middleware that extracts the first path segment (the 'domain')
#     such as 'enterprise' or 'mobile', and attaches it to request.state.domain.
#     """

#     async def dispatch(self, request: Request, call_next):
#         # Extract domain prefix from path
#         path_parts = request.url.path.strip("/").split("/")
#         print(path_parts)
#         domain = path_parts[0] if path_parts and path_parts[0] in domain_base.ALLOWED_DOMAINS else None

#         # Attach to request.state for access in routes
#         request.state.domain = domain_base.ALLOWED_DOMAINS[domain]

#         # Continue the request
#         response = await call_next(request)
#         return response

app = FastAPI()

# app.add_middleware(DomainExtractorMiddleware)

# Include routers (nesting)
app.include_router(domain_base.router)