use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub ports: Vec<u16>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::get_config_path();
        
        if let Some(path) = &config_path {
            if path.exists() {
                let content = fs::read_to_string(path)?;
                let config: Config = toml::from_str(&content)?;
                return Ok(config);
            }
        }

        // Return default config if file doesn't exist or can't be found
        Ok(Config::default())
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config path"))?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(config_path, content)?;
        Ok(())
    }

    pub fn add_port(&mut self, port: u16) -> Result<()> {
        if !self.ports.contains(&port) {
            self.ports.push(port);
            self.ports.sort_unstable();
            self.save()?;
        }
        Ok(())
    }

    pub fn remove_port(&mut self, port: u16) -> Result<()> {
        if let Some(pos) = self.ports.iter().position(|&p| p == port) {
            self.ports.remove(pos);
            self.save()?;
        }
        Ok(())
    }

    fn get_config_path() -> Option<PathBuf> {
        ProjectDirs::from("com", "namanxajmera", "dev-ports-tray")
            .map(|proj_dirs| proj_dirs.config_dir().join("config.toml"))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ports: vec![
                3000, // React, Next.js, create-react-app
                3001, // alternate React
                4200, // Angular
                5000, // Flask, various tools
                5173, // Vite
                5174, // Vite alternate
                8000, // Django, Python HTTP server
                8080, // common HTTP alternative
                8081, // common alternative
                8888, // Jupyter Notebook
                9000, // various tools
                9090, // Prometheus
            ],
        }
    }
}
