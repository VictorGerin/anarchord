//! Barra de entrada da TUI: edição com cursor, histórico (persistido em disco) e Tab para completar.

use std::path::PathBuf;

/// Linhas de histórico mantidas (memória e disco)
const MAX_HISTORY: usize = 500;

/// Comandos conhecidos, para completar com Tab. Os que terminam em espaço esperam argumento.
pub const COMMANDS: &[&str] = &[
    "/help",
    "/peers",
    "/devices",
    "/mute",
    "/quit",
    "/join ",
    "/lobby",
    "/voice join ",
    "/voice leave",
    "/share ",
    "/send ",
    "/get ",
    "/accept ",
    "/reject ",
    "/files",
    "/unshare ",
    "/friend add ",
    "/friend accept ",
    "/friend reject ",
    "/friend resend ",
    "/friend remove ",
    "/friend list",
    "/friends",
    "/dm ",
    "/dm open ",
    "/rotate-key",
    "/firewall",
    "/config",
    "/screen list",
    "/screen start",
    "/screen stop",
    "/screen watch ",
    "/server create ",
    "/server join ",
    "/server accept",
    "/server list",
    "/server switch ",
    "/server info",
    "/server invite",
    "/server channel add ",
    "/server mod add ",
    "/server ban ",
    "/server unban ",
    "/server leave",
    "/server key",
    "/server key renew",
    "/server key transfer ",
    "/server key accept",
];

#[derive(Default)]
pub struct LineEditor {
    chars: Vec<char>,
    /// Posição do cursor em caracteres (0..=len)
    cursor: usize,
    history: Vec<String>,
    /// Linha do histórico sendo exibida (None = editando a linha nova)
    history_pos: Option<usize>,
    /// O que estava sendo digitado antes de navegar no histórico
    draft: String,
    history_file: Option<PathBuf>,
}

impl LineEditor {
    /// Editor sem histórico em disco (ex.: caixas de diálogo)
    pub fn new() -> Self {
        Self::default()
    }

    /// Editor com histórico carregado de (e salvo em) `history_file`
    pub fn with_history_file(history_file: PathBuf) -> Self {
        let history = std::fs::read_to_string(&history_file)
            .map(|text| text.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default();
        let skip = history.len().saturating_sub(MAX_HISTORY);
        Self { history: history[skip..].to_vec(), history_file: Some(history_file), ..Self::default() }
    }

    pub fn text(&self) -> String {
        self.chars.iter().collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Substitui o texto e põe o cursor no fim
    pub fn set(&mut self, text: &str) {
        self.chars = text.chars().collect();
        self.cursor = self.chars.len();
    }

    pub fn insert(&mut self, c: char) {
        self.chars.insert(self.cursor, c);
        self.cursor += 1;
        self.history_pos = None;
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.chars.len() {
            self.chars.remove(self.cursor);
        }
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.chars.len());
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.chars.len();
    }

    /// Linha anterior do histórico (↑)
    pub fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let pos = match self.history_pos {
            None => {
                self.draft = self.text();
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(p) => p - 1,
        };
        self.history_pos = Some(pos);
        let line = self.history[pos].clone();
        self.set(&line);
    }

    /// Próxima linha do histórico (↓); depois da última, volta ao que estava sendo digitado
    pub fn history_next(&mut self) {
        let Some(pos) = self.history_pos else { return };
        if pos + 1 < self.history.len() {
            self.history_pos = Some(pos + 1);
            let line = self.history[pos + 1].clone();
            self.set(&line);
        } else {
            self.history_pos = None;
            let draft = std::mem::take(&mut self.draft);
            self.set(&draft);
        }
    }

    /// Entrega a linha digitada, limpa o editor e guarda a linha no histórico
    pub fn submit(&mut self) -> String {
        let line = self.text();
        self.chars.clear();
        self.cursor = 0;
        self.history_pos = None;
        self.draft.clear();
        let trimmed = line.trim();
        if !trimmed.is_empty() && self.history.last().map(String::as_str) != Some(trimmed) {
            self.history.push(trimmed.to_string());
            if self.history.len() > MAX_HISTORY {
                self.history.remove(0);
            }
            self.save_history();
        }
        line
    }

    fn save_history(&self) {
        if let Some(path) = &self.history_file {
            let _ = std::fs::write(path, self.history.join("\n") + "\n");
        }
    }

    /// Completa com Tab. Começando com `/`, completa comandos; senão (ou quando nenhum comando
    /// casa), completa a última palavra com `words` (nicks e canais).
    /// Retorna as opções quando há mais de uma, para a interface mostrar.
    pub fn complete(&mut self, words: &[String]) -> Vec<String> {
        let text = self.text();
        if text.starts_with('/') {
            let matches: Vec<String> = COMMANDS.iter().filter(|c| c.starts_with(&text)).map(|c| c.to_string()).collect();
            if !matches.is_empty() {
                return self.apply_completion("", &text, matches);
            }
        }
        let start = text.rfind(' ').map_or(0, |i| i + 1);
        let (head, word) = text.split_at(start);
        if word.is_empty() {
            return Vec::new();
        }
        let lower = word.to_lowercase();
        let mut matches: Vec<String> = words.iter().filter(|w| w.to_lowercase().starts_with(&lower)).cloned().collect();
        matches.sort();
        matches.dedup();
        if matches.len() == 1 {
            matches[0].push(' ');
        }
        self.apply_completion(head, word, matches)
    }

    fn apply_completion(&mut self, head: &str, typed: &str, matches: Vec<String>) -> Vec<String> {
        match matches.len() {
            0 => Vec::new(),
            1 => {
                self.set(&format!("{}{}", head, matches[0]));
                Vec::new()
            }
            _ => {
                let prefix = common_prefix(&matches);
                if prefix.chars().count() >= typed.chars().count() {
                    self.set(&format!("{}{}", head, prefix));
                }
                matches
            }
        }
    }
}

fn common_prefix(items: &[String]) -> String {
    let mut prefix: Vec<char> = items[0].chars().collect();
    for item in &items[1..] {
        let shared = prefix.iter().zip(item.chars()).take_while(|(a, b)| **a == *b).count();
        prefix.truncate(shared);
    }
    prefix.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor_with(text: &str) -> LineEditor {
        let mut e = LineEditor::new();
        e.set(text);
        e
    }

    #[test]
    fn test_cursor_editing_in_the_middle() {
        let mut e = editor_with("ola mundo");
        e.home();
        e.right();
        e.right();
        e.insert('á');
        assert_eq!(e.text(), "oláa mundo");
        e.delete();
        assert_eq!(e.text(), "olá mundo");
        e.end();
        e.backspace();
        assert_eq!(e.text(), "olá mund");
        assert_eq!(e.cursor(), 8);
    }

    #[test]
    fn test_history_navigation_restores_draft() {
        let mut e = LineEditor::new();
        e.set("primeira");
        e.submit();
        e.set("segunda");
        e.submit();
        e.set("rascunho");

        e.history_prev();
        assert_eq!(e.text(), "segunda");
        e.history_prev();
        assert_eq!(e.text(), "primeira");
        e.history_prev();
        assert_eq!(e.text(), "primeira", "não passa do início");
        e.history_next();
        assert_eq!(e.text(), "segunda");
        e.history_next();
        assert_eq!(e.text(), "rascunho", "volta ao que estava sendo digitado");
    }

    #[test]
    fn test_history_skips_empty_and_repeated_lines() {
        let mut e = LineEditor::new();
        for line in ["oi", "oi", "   ", "tchau"] {
            e.set(line);
            e.submit();
        }
        e.history_prev();
        assert_eq!(e.text(), "tchau");
        e.history_prev();
        assert_eq!(e.text(), "oi");
        e.history_prev();
        assert_eq!(e.text(), "oi");
    }

    #[test]
    fn test_history_persists_between_sessions() {
        let path = std::env::temp_dir().join(format!("anarchord_history_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut e = LineEditor::with_history_file(path.clone());
            e.set("/server create Rust Guild");
            e.submit();
        }
        let mut e = LineEditor::with_history_file(path.clone());
        e.history_prev();
        assert_eq!(e.text(), "/server create Rust Guild");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_tab_completes_commands() {
        let mut e = editor_with("/ser");
        let options = e.complete(&[]);
        assert_eq!(e.text(), "/server ", "prefixo comum dos comandos /server");
        assert!(options.len() > 5);

        let mut e = editor_with("/server cr");
        assert!(e.complete(&[]).is_empty());
        assert_eq!(e.text(), "/server create ");

        let mut e = editor_with("/he");
        e.complete(&[]);
        assert_eq!(e.text(), "/help");
    }

    #[test]
    fn test_tab_completes_nicks_after_command() {
        let words = vec!["Bob".to_string(), "Bruna".to_string(), "Alice".to_string()];
        let mut e = editor_with("/server ban bo");
        e.complete(&words);
        assert_eq!(e.text(), "/server ban Bob ");

        let mut e = editor_with("oi b");
        let options = e.complete(&words);
        assert_eq!(options, vec!["Bob".to_string(), "Bruna".to_string()]);
        assert_eq!(e.text(), "oi B", "completa até o prefixo comum");
    }
}
