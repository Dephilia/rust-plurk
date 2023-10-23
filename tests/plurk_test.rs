use rust_plurk::plurk::Plurk;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_plurk() {
        let plurk = Plurk::new("123", "abc", None, None);
        let res = format!("{}", plurk);
        assert_eq!(res, "Plurk API 123 (Unauthorized)");

        let plurk = Plurk::new("123", "abc", Some("ttt"), None);
        let res = format!("{}", plurk);
        assert_eq!(res, "Plurk API 123 (Unauthorized)");

        let plurk = Plurk::new("123", "abc", None, Some("AAA"));
        let res = format!("{}", plurk);
        assert_eq!(res, "Plurk API 123 (Unauthorized)");

        let plurk = Plurk::new("123", "abc", Some("ttt"), Some("AAA"));
        let res = format!("{}", plurk);
        assert_eq!(res, "Plurk API 123 (Authorized)");
    }

    #[tokio::test]
    async fn test_auth_flow() {
        let mut plurk = Plurk::new(
            "z3kiB2tbqrlC",
            "u8mCwet8BQNjROfUZU8A6BHc1o9rx1AE",
            None,
            None,
        );
        // TODO: Add test case
        let _ = plurk.request_auth().await;
        let _ = plurk.get_auth_url();
        let _ = plurk.verify_auth("1234").await;
    }
}
