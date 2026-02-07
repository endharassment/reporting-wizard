package email

import (
	"io/ioutil"
	"log"
	"net/mail"
	"regexp"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/endharassment/reporting-wizard/internal/model"
	"github.com/endharassment/reporting-wizard/internal/store"
	"github.com/google/uuid"
	"golang.org/x/net/context"
)


// IMAPConfig holds the configuration for the IMAP client.
type IMAPConfig struct {
	Server   string
	Username string
	Password string
}

// FetchAndProcessEmails connects to the IMAP server, fetches new emails,
// and processes them.
func FetchAndProcessEmails(cfg IMAPConfig, s store.Store) {
	log.Println("Connecting to IMAP server...")
	c, err := client.DialTLS(cfg.Server, nil)
	if err != nil {
		log.Printf("ERROR: imap dial: %v", err)
		return
	}
	log.Println("Connected to IMAP server")
	defer c.Logout()

	if err := c.Login(cfg.Username, cfg.Password); err != nil {
		log.Printf("ERROR: imap login: %v", err)
		return
	}
	log.Println("Logged in to IMAP server")

	if _, err := c.Select("INBOX", false); err != nil {
		log.Printf("ERROR: imap select inbox: %v", err)
		return
	}

	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{imap.SeenFlag}
	ids, err := c.Search(criteria)
	if err != nil {
		log.Printf("ERROR: imap search: %v", err)
		return
	}

	if len(ids) == 0 {
		log.Println("No new emails")
		return
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(ids...)

		messages := make(chan *imap.Message, 10)
		done := make(chan error, 1)
		section := &imap.BodySectionName{}
		items := []imap.FetchItem{section.FetchItem()}
	
		go func() {
			done <- c.Fetch(seqset, items, messages)
		}()
	
		ticketIDRegex := regexp.MustCompile(`\[Ticket: ([^\]]+)\]`)
	
		for msg := range messages {
			r := msg.GetBody(section)
			if r == nil {
				log.Printf("ERROR: server didn't return message body for %d", msg.SeqNum)
				continue
			}
	
			m, err := mail.ReadMessage(r)
			if err != nil {
				log.Printf("ERROR: reading message %d: %v", msg.SeqNum, err)
				continue
			}
	
			header := m.Header
			subject := header.Get("Subject")
			from, _ := header.AddressList("From")
			fromAddress := ""
			if len(from) > 0 {
				fromAddress = from[0].Address
			}
	
			emailID := ""
			matches := ticketIDRegex.FindStringSubmatch(subject)
			if len(matches) > 1 {
				emailID = matches[1]
			}
	
			if emailID == "" {
				continue
			}
	
			// Check if email with this ID exists
			outgoingEmail, err := s.GetOutgoingEmail(context.Background(), emailID)
			if err != nil {
				log.Printf("INFO: received reply for unknown ticket %s", emailID)
				continue
			}
	
			body, err := ioutil.ReadAll(m.Body)
			if err != nil {
				log.Printf("ERROR: reading body for message %d: %v", msg.SeqNum, err)
				continue
			}
	
			reply := &model.EmailReply{
				ID:              uuid.New().String(),
				OutgoingEmailID: emailID,
				FromAddress:     fromAddress,
				Body:            string(body),
				CreatedAt:       time.Now().UTC(),
			}
	
			if err := s.CreateEmailReply(context.Background(), reply); err != nil {
				log.Printf("ERROR: creating email reply: %v", err)
				continue
			}

			log.Printf("Saved reply to ticket %s from %s", emailID, fromAddress)

			// Check if the reply came too soon after the original email was sent.
			// This is to avoid stopping escalation due to an automated reply.
			const autoReplyGracePeriod = 20 * time.Minute
			if outgoingEmail.SentAt != nil {
				if time.Since(*outgoingEmail.SentAt) < autoReplyGracePeriod {
					log.Printf("INFO: Reply for ticket %s received within grace period (%s since sent). Ignoring for escalation purposes.", emailID, time.Since(*outgoingEmail.SentAt).Round(time.Second))
				} else {
					// Prevent escalation by marking the email as replied.
					outgoingEmail.ResponseNotes = "Replied by " + fromAddress + " at " + time.Now().UTC().Format(time.RFC3339)
					if err := s.UpdateOutgoingEmail(context.Background(), outgoingEmail); err != nil {
						log.Printf("ERROR: updating outgoing email %s after reply: %v", emailID, err)
						continue
					}
					log.Printf("Updated outgoing email %s to prevent escalation.", emailID)
				}
			} else {
				log.Printf("WARNING: Outgoing email %s has no SentAt timestamp. Cannot apply auto-reply grace period.", emailID)
				// Default to marking as replied if SentAt is missing to be safe,
				// or decide to always escalate if SentAt is missing.
				// For now, let's assume SentAt should always be present for sent emails.
				// If not present, we will still update ResponseNotes, as it's better to
				// err on the side of not escalating than potentially over-escalating.
				outgoingEmail.ResponseNotes = "Replied by " + fromAddress + " at " + time.Now().UTC().Format(time.RFC3339)
				if err := s.UpdateOutgoingEmail(context.Background(), outgoingEmail); err != nil {
					log.Printf("ERROR: updating outgoing email %s after reply (no SentAt): %v", emailID, err)
					continue
				}
				log.Printf("Updated outgoing email %s to prevent escalation (no SentAt, assumed genuine).", emailID)
			}
	
			// Mark email as seen
			seqsetMark := new(imap.SeqSet)
			seqsetMark.AddNum(msg.SeqNum)
			item := imap.FormatFlagsOp(imap.AddFlags, true)
			flags := []interface{}{imap.SeenFlag}
			if err := c.Store(seqsetMark, item, flags, nil); err != nil {
				log.Printf("ERROR: marking email as seen: %v", err)
			}
		}
	
		if err := <-done; err != nil {
			log.Printf("ERROR: imap fetch: %v", err)
		}
	}
