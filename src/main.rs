use std::io::{self, Write};
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use hex::{encode, decode};
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, List, ListItem, Paragraph, ListState, Clear},
    layout::{Layout, Constraint, Direction, Rect},
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

enum InputField { Name, Guilt, Reason }
enum Mode { View, Add }

const DB_FILE: &str = "kuzya_targets.encrypted";
const KEY_FILE: &str = "kuzya_db.key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (cipher, key_hex_str) = load_or_generate_key();
    let mut black_list = load_db_internal(&cipher);
    
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut state = ListState::default();
    if !black_list.is_empty() { state.select(Some(0)); }

    let mut mode = Mode::View;
    let mut input_name = String::new();
    let mut input_guilt = String::new();
    let mut input_reason = String::new();
    let mut active_field = InputField::Name;

    loop {
        terminal.draw(|f| {
            ui(f, &black_list, &key_hex_str, &mut state);
            if let Mode::Add = mode {
                render_popup(f, &input_name, &input_guilt, &input_reason, &active_field);
            }
        })?;

        if let Event::Key(key) = event::read()? {
            match mode {
                Mode::View => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('n') => { mode = Mode::Add; active_field = InputField::Name; }
                    KeyCode::Char('d') => {
                        if let Some(selected) = state.selected() {
                            black_list.remove(selected);
                            save_db_internal(&cipher, &black_list);
                            if black_list.is_empty() { state.select(None); }
                            else if selected >= black_list.len() { state.select(Some(black_list.len()-1)); }
                        }
                    }
                    KeyCode::Down => {
                        let i = match state.selected() {
                            Some(i) => if i >= black_list.len() - 1 { 0 } else { i + 1 },
                            None => 0,
                        };
                        state.select(Some(i));
                    }
                    KeyCode::Up => {
                        let i = match state.selected() {
                            Some(i) => if i == 0 { black_list.len() - 1 } else { i - 1 },
                            None => 0,
                        };state.select(Some(i));
                    }
                    _ => {}
                },
                Mode::Add => match key.code {
                    KeyCode::Esc => mode = Mode::View,
                    KeyCode::Tab => {
                        active_field = match active_field {
                            InputField::Name => InputField::Guilt,
                            InputField::Guilt => InputField::Reason,
                            InputField::Reason => InputField::Name,
                        };
                    }
                    KeyCode::Enter => {
                        let guilt = input_guilt.parse::<u32>().unwrap_or(0);
                        black_list.push(Suspect { name: input_name.clone(), guilt_level: guilt, reason: input_reason.clone() });
                        save_db_internal(&cipher, &black_list);
                        // Сброс
                        input_name.clear(); input_guilt.clear(); input_reason.clear();
                        mode = Mode::View;
                        state.select(Some(black_list.len() - 1));
                    }
                    KeyCode::Char(c) => match active_field {
                        InputField::Name => input_name.push(c),
                        InputField::Guilt => if c.is_digit(10) { input_guilt.push(c) },
                        InputField::Reason => input_reason.push(c),
                    },
                    KeyCode::Backspace => match active_field {
                        InputField::Name => { input_name.pop(); }
                        InputField::Guilt => { input_guilt.pop(); }
                        InputField::Reason => { input_reason.pop(); }
                    },
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

fn ui(f: &mut Frame, list: &[Suspect], key: &str, state: &mut ListState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)].as_ref())
        .split(f.size());

    let theme_color = Color::Rgb(0, 170, 255);
    f.render_widget(Block::default().style(Style::default().bg(Color::Rgb(15, 15, 20))), f.size());

    f.render_widget(Paragraph::new(" [ KUZYA INTELLIGENCE DATABASE v2.4 FULL CONTROL ] ")
        .style(Style::default().fg(theme_color).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme_color))), chunks[0]);

    let max_name_len = list.iter().map(|s| s.name.len()).max().unwrap_or(15).max(15);
    let items: Vec<ListItem> = list.iter().map(|s| {
        let (status, color) = match s.guilt_level {
            100 => ("ТЕРРОРИСТ", Color::Rgb(255, 0, 0)),
            60..=99 => ("ЕРЕТИК", Color::Rgb(255, 100, 0)),
            30..=59 => ("ПОДОЗРЕВАЕМЫЙ", Color::Yellow),
            0 => ("НЕЙТРАЛЬНЫЙ", Color::Rgb(0, 255, 150)),
            _ => ("UNKNOWN", Color::Rgb(150, 150, 150)),
        };
        ListItem::new(format!(" > {:<width$} │ {:>3}% │ {:<14} │ ПРИЧИНА: {}", s.name, s.guilt_level, status, s.reason, width = max_name_len)).style(Style::default().fg(color))
    }).collect();

    let list_widget = List::new(items)
        .block(Block::default().title(" РЕЕСТР ЕРЕТИКОВ НА УТИЛИЗАЦИЮ КРОШЕК ").borders(Borders::ALL).border_style(Style::default().fg(theme_color)))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED).fg(theme_color)).highlight_symbol(">> ");
    f.render_stateful_widget(list_widget, chunks[1], state);

    f.render_widget(Paragraph::new(format!(" Q:ВЫХОД │ N:НОВЫЙ │ D:УДАЛИТЬ │ KEY:{}... ", &key[..8]))
        .style(Style::default().fg(Color::DarkGray)).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme_color))), chunks[2]);
}

fn render_popup(f: &mut Frame, name: &str, guilt: &str, reason: &str, active: &InputField) {
    let area = centered_rect(60, 40, f.size());
    f.render_widget(Clear, area); // Очистка фона под окном
    let block = Block::default().title(" РЕГИСТРАЦИЯ ЕРЕТИКА ").borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow));
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(area);

    let mk_field = |label, value, is_active| {
        Paragraph::new(value).block(Block::default().title(label).borders(Borders::ALL)
            .border_style(Style::default().fg(if is_active { Color::Cyan } else { Color::Gray })))
    };

    f.render_widget(mk_field(" Ник ", name, matches!(active, InputField::Name)), chunks[0]);
    f.render_widget(mk_field(" Вина (0-100) ", guilt, matches!(active, InputField::Guilt)), chunks[1]);
    f.render_widget(mk_field(" Причина ", reason, matches!(active, InputField::Reason)), chunks[2]);
    f.render_widget(Paragraph::new(" [TAB] Переключить │ [ENTER] Сохранить │ [ESC] Отмена ").style(Style::default().fg(Color::DarkGray)), chunks[3]);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage((100 - percent_y) / 2), Constraint::Percentage(percent_y), Constraint::Percentage((100 - percent_y) / 2)].as_ref())
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage((100 - percent_x) / 2), Constraint::Percentage(percent_x), Constraint::Percentage((100 - percent_x) / 2)].as_ref())
        .split(popup_layout[1])[1]
}

// Загрузка/Сохранение и Ключ остаются (load_or_generate_key, load_db_internal, save_db_internal)
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
