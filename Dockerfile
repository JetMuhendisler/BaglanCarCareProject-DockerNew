# --- Stage 1: Frontend Build ---
FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install --legacy-peer-deps
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Backend Build ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS backend-build
WORKDIR /src
COPY backend/BaglanCarCare.Domain/BaglanCarCare.Domain.csproj BaglanCarCare.Domain/
COPY backend/BaglanCarCare.Application/BaglanCarCare.Application.csproj BaglanCarCare.Application/
COPY backend/BaglanCarCare.Persistence/BaglanCarCare.Persistence.csproj BaglanCarCare.Persistence/
COPY backend/BaglanCarCare.WebApi/BaglanCarCare.WebApi.csproj BaglanCarCare.WebApi/
RUN dotnet restore "BaglanCarCare.WebApi/BaglanCarCare.WebApi.csproj"

COPY backend/ ./
RUN dotnet publish "BaglanCarCare.WebApi/BaglanCarCare.WebApi.csproj" -c Release -o /app/publish

# --- Stage 3: Final Image ---
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

# Copy Backend
COPY --from=backend-build /app/publish .

# Copy Frontend to wwwroot
COPY --from=frontend-build /app/dist ./wwwroot

ENTRYPOINT ["dotnet", "BaglanCarCare.WebApi.dll"]
