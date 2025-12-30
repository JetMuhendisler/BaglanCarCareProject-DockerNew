using System;

namespace BaglanCarCare.Application.DTOs
{
    public class CreateDeletionRequestDto
    {
        public string TargetEntityName { get; set; }
        public int TargetId { get; set; }
        public string Note { get; set; }
    }

    public class DeletionRequestListDto
    {
        public int Id { get; set; }
        public string RequesterName { get; set; }
        public string TargetEntityName { get; set; }
        public int TargetId { get; set; }
        public string Note { get; set; }
        public string Status { get; set; }
        public DateTime CreatedDate { get; set; }
    }
}
