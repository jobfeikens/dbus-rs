use std::borrow::Cow;
use std::collections::HashMap;
use crate::{Message, MessageType};
use crate::strings::{BusName, Path, Interface, Member};
use crate::message::parser;

#[derive(Clone, Debug, Default)]
/// A "match rule", that can match Messages on its headers.
///
/// A field set to "None" means no filter for that header,
/// a field set to "Some(_)" must match exactly.
pub struct MatchRule<'a> {
    /// Match on message type (you typically want to do this)
    pub msg_type: Option<MessageType>,
    /// Match on message sender
    pub sender: Option<BusName<'a>>,
    /// If false (the default), match if sender could possibly match, due to mismatch between unique names and taken bus names
    pub strict_sender: bool,
    /// Match on message object path
    pub path: Option<Path<'a>>,
    /// If true, will match all subpaths to the path as well as the path itself. Defaults to false.
    pub path_is_namespace: bool,
    /// Match on message interface
    pub interface: Option<Interface<'a>>,
    /// Match on message member (signal or method name)
    pub member: Option<Member<'a>>,
    /// If true, also receive messages not intended for us. Defaults to false.
    pub eavesdrop: bool,
    /// Match on message arguments (only string arguments will match)
    pub args: HashMap<usize, String>,
    _more_fields_may_come: (),
}

fn msg_type_str(m: MessageType) -> &'static str {
    use crate::MessageType::*;
    match m {
        Signal => "signal",
        MethodCall => "method_call",
        MethodReturn => "method_return",
        Error => "error",
    }
}


impl<'a> MatchRule<'a> {
    /// Make a string which you can use in the call to "add_match".
    pub fn match_str(&self) -> String {
        let mut v = vec!();
        if let Some(x) = self.msg_type { v.push((Cow::Borrowed("type"), msg_type_str(x))) };
        if let Some(ref x) = self.sender { v.push((Cow::Borrowed("sender"), &x)) };
        let pn = if self.path_is_namespace { "path_namespace" } else { "path" };
        if let Some(ref x) = self.path { v.push((Cow::Borrowed(pn), &x)) };
        if let Some(ref x) = self.interface { v.push((Cow::Borrowed("interface"), &x)) };
        if let Some(ref x) = self.member { v.push((Cow::Borrowed("member"), &x)) };
        if self.eavesdrop { v.push((Cow::Borrowed("eavesdrop"), "true")) };
        for (arg, value) in &self.args {
            v.push((Cow::Owned(format!("arg{}", arg)), value));
        }

        // For now we don't need to worry about internal quotes in strings as those are not valid names.
        // If we start matching against arguments, we need to worry.
        let v: Vec<_> = v.into_iter().map(|(k, v)| format!("{}='{}'", k, v)).collect();
        v.join(",")
    }

    fn path_match(&self, msg: &Message) -> bool {
        if let Some(ref x) = self.path {
            if let Some(ref p) = msg.path() {
                if x != p {
                    if self.path_is_namespace {
                        p.starts_with(&**x) && &p[x.len()..x.len() + 1] == "/"
                    } else { false }
                } else { true }
            } else { false }
        } else { true }
    }

    /// Returns whether or not the message matches the rule.
    pub fn matches(&self, msg: &Message) -> bool {
        if let Some(x) = self.msg_type { if x != msg.msg_type() { return false; } };

        if let Some(ref x) = self.sender {
            if let Some(s) = msg.sender() {
                let check = self.strict_sender || (s.starts_with(":") == x.starts_with(":"));
                if check && s != *x { return false; }
            } else if self.strict_sender { return false; }
        };
        if !self.path_match(msg) { return false; }
        if self.interface.is_some() && msg.interface() != self.interface { return false; };
        if self.member.is_some() && msg.member() != self.member { return false; };
        true
    }

    /// Create a new struct which matches every message.
    pub fn new() -> Self { Default::default() }

    /// Create a new struct which matches every incoming method call message.
    pub fn new_method_call() -> Self {
        let mut m = Self::new();
        m.msg_type = Some(MessageType::MethodCall);
        m
    }

    /// Create a new struct which matches signals on the interface and member name.
    pub fn new_signal<I: Into<Interface<'a>>, N: Into<Member<'a>>>(intf: I, name: N) -> Self {
        let mut m = Self::new();
        m.msg_type = Some(MessageType::Signal);
        m.interface = Some(intf.into());
        m.member = Some(name.into());
        m
    }

    /// Returns a clone with no borrowed references
    pub fn static_clone(&self) -> MatchRule<'static> {
        MatchRule {
            msg_type: self.msg_type,
            sender: self.sender.as_ref().map(|x| x.clone().into_static()),
            strict_sender: self.strict_sender,
            path: self.path.as_ref().map(|x| x.clone().into_static()),
            interface: self.interface.as_ref().map(|x| x.clone().into_static()),
            member: self.member.as_ref().map(|x| x.clone().into_static()),
            path_is_namespace: self.path_is_namespace,
            eavesdrop: self.eavesdrop,
            args: self.args.clone(),
            _more_fields_may_come: (),
        }
    }

    /// Enables eavesdropping for the generated message.
    /// You probably want to use [BecomeMonitor](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-become-monitor) instead
    pub fn with_eavesdrop(mut self) -> Self {
        self.eavesdrop = true;
        self
    }

    /// Sets the MatchRule to match on the message sender
    pub fn with_sender(mut self, sender: impl Into<BusName<'a>>) -> Self {
        self.sender = Some(sender.into());
        self
    }

    /// Sets the MatchRule to match on the message sender and be strict
    pub fn with_strict_sender(mut self, sender: impl Into<BusName<'a>>) -> Self {
        self.sender = Some(sender.into());
        self.strict_sender = true;
        self
    }

    /// Sets the MatchRule to match on the message path and treat it as a namespace
    pub fn with_namespaced_path(mut self, path: impl Into<Path<'a>>) -> Self {
        self.path = Some(path.into());
        self.path_is_namespace = true;
        self
    }

    /// Sets the MatchRule to match on the message path
    pub fn with_path(mut self, path: impl Into<Path<'a>>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the MatchRule to match on the message interface
    pub fn with_interface(mut self, intf: impl Into<Interface<'a>>) -> Self {
        self.interface = Some(intf.into());
        self
    }

    /// Sets the MatchRule to match on the message member
    pub fn with_member(mut self, member: impl Into<Member<'a>>) -> Self {
        self.member = Some(member.into());
        self
    }

    /// Sets the MatchRule to match on the message type. This will usually be `"signal"`
    pub fn with_type(mut self, ty: MessageType) -> Self {
        self.msg_type = Some(ty);
        self
    }

    /// Sets the MatchRule to match on an argument.
    /// Function will panic when index is set to a value greater than DBUS_MAXIMUM_MATCH_RULE_ARG_NUMBER (63).
    pub fn with_arg(mut self, index: usize, value: impl Into<String>) -> Self {
        assert!(index <= 63);
        self.args.insert(index, value.into());
        self
    }

    /// Tries parsing a MatchRule from a String. Please note however that not all features supported
    /// by DBus are supported by dbus-rs (yet). args and destinations are not supported yet.
    pub fn parse(text: &'a str) -> Result<Self, parser::Error> {
        parser::Parser::new(text)?.parse()
    }
}