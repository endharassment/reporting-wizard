package server

import (
	"net/http"
)

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement admin dashboard
	s.render(w, r, "admin/dashboard.html", nil)
}

func (s *Server) adminQueue(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement admin queue
	s.render(w, r, "admin/queue.html", nil)
}

func (s *Server) adminReport(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement admin report view
	s.render(w, r, "admin/report.html", nil)
}

func (s *Server) adminReportAbuse(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement admin report abuse view
	s.render(w, r, "admin/report_abuse.html", nil)
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement admin users view
	s.render(w, r, "admin/users.html", nil)
}
