using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using BookStoreAppUpdated.Models;

namespace BookStoreAppUpdated.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PublishersController : ControllerBase
    {
        private readonly BookStoresDBContext _context;

        public PublishersController(BookStoresDBContext context)
        {
            _context = context;
        }

        // GET: api/Publishers
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Publisher>>> GetPublishers()
        {
            return await _context.Publishers.ToListAsync();
        }

        // GET: api/Publishers/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Publisher>> GetPublisher(int id)
        {
            var publisher = await _context.Publishers.FindAsync(id);

            if (publisher == null)
            {
                return NotFound();
            }

            return publisher;
        }

        // GET: api/Publishers/5
        [HttpGet("GetPublisherDetails/{id}")]
        public async Task<ActionResult<Publisher>> GetPublisherDetails(int id)
        {
            // Eager Loading
            //var publisher = await _context.Publishers
            //                .Include(pub => pub.Books)
            //                    .ThenInclude(book => book.Sales)
            //                .Include(pub => pub.Users)
            //                .Where(pub => pub.PubId == id)
            //                .FirstOrDefaultAsync();
            //    ;

            // Explicit Loading
            var publisher = await _context.Publishers.SingleAsync(pub => pub.PubId==id);

            _context.Entry(publisher)
                .Collection(pub =>pub.Users)       
                .Query()
                .Where(user => user.LastName.Contains("ibsen"))
                .Load();

            _context.Entry(publisher)
                .Collection(pub => pub.Books)
                .Query()
                .Include(book => book.Sales)
                .Load();

            // Get one value
            var user = await _context.Users.SingleAsync(usr => usr.UserId == 1);
            _context.Entry(user)
                .Reference(usr => usr.Role)
                .Load();

            if (publisher == null)
            {
                return NotFound();
            }

            return publisher;
        }


        // PUT: api/Publishers/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutPublisher(int id, Publisher publisher)
        {
            if (id != publisher.PubId)
            {
                return BadRequest();
            }

            _context.Entry(publisher).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!PublisherExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/Publishers
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<Publisher>> PostPublisher(Publisher publisher)
        {
            _context.Publishers.Add(publisher);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetPublisher", new { id = publisher.PubId }, publisher);
        }


        [HttpPost("PostPublisherDetails/")]
        public async Task<ActionResult<Publisher>> PostPublisherDetails()
        {
            var publisher = new Publisher();
            publisher.PublisherName = "123 Krishna Publishing";
            publisher.City = "London";
            publisher.Country = "UK";
            publisher.State = "LD";

            var book = new Book();
            book.Title = "New Book2";
            book.PublishedDate = DateTime.UtcNow;

            var sale = new Sale();
            sale.Quantity = 10;            
            sale.OrderDate = DateTime.UtcNow;
            sale.OrderNum = "ABC";
            sale.StoreId = "8042";
            sale.PayTerms = "Text";

            book.Sales.Add(sale);
            publisher.Books.Add(book);
            _context.Publishers.Add(publisher);
            await _context.SaveChangesAsync();

            var publishers = await _context.Publishers
                                        .Include(pub => pub.Books)
                                            .ThenInclude(book =>book.Sales)
                                        .Where(pub => pub.PubId == publisher.PubId)
                                        .FirstOrDefaultAsync();
                                            
            return CreatedAtAction("GetPublisher", new { id = publisher.PubId }, publisher);
        }

        // DELETE: api/Publishers/5 
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeletePublisher(int id)
        {
            var publisher = await _context.Publishers.FindAsync(id);
            if (publisher == null)
            {
                return NotFound();
            }

            _context.Publishers.Remove(publisher);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool PublisherExists(int id)
        {
            return _context.Publishers.Any(e => e.PubId == id);
        }
    }
}
