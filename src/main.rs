use std::io::{self, Write};
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use hex::{encode, decode};
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    Terminal, Frame,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Suspect {
    name: String,
    guilt_level: u32,
    reason: String,
}

const DB_FILE: &str = "kuzya_targets.encrypted";
const KEY_FILE: &str = "kuzya_db.key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (cipher, key_hex_str) = load_or_generate_key();
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "add" {
        println!("--- РЕЖИМ РЕГИСТРАЦИИ ЕРЕТИКОВ ---");
        let mut black_list = load_db_internal(&cipher);
        loop {
            print!("\nНик (или 'exit'): ");
            io::stdout().flush()?;
            let mut name_buf = String::new();
            io::stdin().read_line(&mut name_buf)?;
            let name = name_buf.trim().to_string();
            if name == "exit" || name.is_empty() { break; }

            print!("Вина (0-100): ");
            io::stdout().flush()?;
            let mut lvl_buf = String::new();
            io::stdin().read_line(&mut lvl_buf)?;
            let level: u32 = lvl_buf.trim().parse().unwrap_or(0);

            print!("Причина занесения: "); // ЗАПРОС ПРИЧИНЫ
            io::stdout().flush()?;
            let mut r_buf = String::new();
            io::stdin().read_line(&mut r_buf)?;
            let reason = r_buf.trim().to_string();

            black_list.push(Suspect { name, guilt_level: level, reason });
            println!(">>> Объект упакован.");
        }
        save_db_internal(&cipher, &black_list);
        return Ok(());
    }

    if args.len() > 1 && args[1] == "del" {
        let mut black_list = load_db_internal(&cipher);
        println!("Удаление объекта...");
        let mut name_buf = String::new();
        io::stdin().read_line(&mut name_buf)?;
        black_list.retain(|s| s.name != name_buf.trim());
        save_db_internal(&cipher, &black_list);
        return Ok(());
    }

    // РЕЖИМ ИНТЕРФЕЙСА
    let black_list = load_db_internal(&cipher);
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    loop {
        terminal.draw(|f| ui(f, &black_list, &key_hex_str))?;
        if let Event::Key(key) = event::read()? {
            if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc { break; }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

fn ui(f: &mut Frame, list: &[Suspect], key: &str) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)].as_ref())
        .split(size);

    let theme_color = Color::Rgb(0, 170, 255);
    let bg_color = Color::Rgb(15, 15, 20);
    f.render_widget(Block::default().style(Style::default().bg(bg_color)), size);

    // ЗАГОЛОВОК
    f.render_widget(Paragraph::new(" [ KUZYA INTELLIGENCE DATABASE v2.2 ] ")
        .style(Style::default().fg(theme_color).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme_color))), chunks[0]);

    let max_name_len = list.iter().map(|s| s.name.len()).max().unwrap_or(15).max(15);
    
    let items: Vec<ListItem> = list.iter().map(|s| {
        // ОБНОВЛЕНИЕ СТАТУСОВ
        let (status, color) = match s.guilt_level {
            100 => ("ТЕРРОРИСТ", Color::Rgb(255, 0, 0)),        // Ярко-красный
            60..=99 => ("ЕРЕТИК", Color::Rgb(255, 100, 0)),    // Оранжевый
            30..=59 => ("ПОДОЗРЕВАЕМЫЙ", Color::Yellow),       // Желтый
            1..=29 => ("ПОСОБНИК", Color::Rgb(150, 150, 150)), // Серый
            0 => ("НЕЙТРАЛЬНЫЙ", Color::Rgb(0, 255, 150)),           // Неоново-зеленый
            _ => ("UNKNOWN", Color::White),
        };

        let content = format!(
            " > {:<width$} │ {:>3}% │ {:<14} │ ПРИЧИНА: {}",
            s.name, s.guilt_level, status, s.reason, width = max_name_len
        );

        ListItem::new(content).style(Style::default().fg(color))
    }).collect();

    let list_widget = List::new(items)
        .block(Block::default().title(" РЕЕСТР ХЕЙТЕРОВ СНЕКОВ 'КУЗЯ' " ).borders(Borders::ALL).border_style(Style::default().fg(theme_color)));
    f.render_widget(list_widget, chunks[1]);

    f.render_widget(Paragraph::new(format!(" KEY: {}... │ Q: ВЫХОД ", &key[..12]))
        .style(Style::default().fg(Color::DarkGray)).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme_color))), chunks[2]);
}

fn load_or_generate_key() -> (Aes256Gcm, String) {
    if Path::new(KEY_FILE).exists() {
        let key_hex = fs::read_to_string(KEY_FILE).unwrap();
        let key_bytes = decode(key_hex.trim()).unwrap();
        (Aes256Gcm::new_from_slice(&key_bytes).unwrap(), key_hex)
    } else {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let key_hex = encode(&key_bytes);
        fs::write(KEY_FILE, &key_hex).unwrap();
        (Aes256Gcm::new_from_slice(&key_bytes).unwrap(), key_hex)
    }
}

fn load_db_internal(cipher: &Aes256Gcm) -> Vec<Suspect> {
    if let Ok(encrypted_data) = fs::read(DB_FILE) {
        if encrypted_data.len() > 12 {
            let nonce = Nonce::from_slice(&encrypted_data[..12]);
            if let Ok(decrypted) = cipher.decrypt(nonce, &encrypted_data[12..]) {
                if let Ok(list) = serde_json::from_slice(&decrypted) { return list; }
            }
        }
    }
    Vec::new()
}

fn save_db_internal(cipher: &Aes256Gcm, list: &Vec<Suspect>) {
    if let Ok(json_bytes) = serde_json::to_vec(list) {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        if let Ok(ct) = cipher.encrypt(nonce, json_bytes.as_slice()) {
            let mut data = nonce_bytes.to_vec();
            data.extend_from_slice(&ct);
            fs::write(DB_FILE, data).unwrap();
        }
    }
}
